package settings

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/redis/go-redis/v9"
)

// Applier receives settings that have already been parsed and validated.
// Returning an error means the settings were refused and the previous ones are
// still in force.
type Applier func(config.EnforcementConfig) error

// Watcher polls Redis for the console's override and applies it.
//
// It follows the same rules as the policy store, for the same reason: Redis
// going down must never take the gateway with it. A failed read keeps the
// settings already in force rather than falling back to anything.
type Watcher struct {
	client   *redis.Client
	interval time.Duration

	// The settings the gateway booted with. Deleting the override key returns
	// the gateway to exactly these, which is what "revert to the file" means.
	boot config.EnforcementConfig

	apply Applier

	// The raw JSON last seen, so an unchanged key is neither re-applied nor
	// re-logged every tick. This is what was *offered*, which is not the same
	// as what is running: an override that was refused is recorded here so it
	// is not retried, but it never becomes the effective settings.
	seen string

	// What is actually in force, and where it came from. Only ever updated
	// after an apply has succeeded, because this is what gets published and
	// the console draws its form from it -- reporting a refused override as
	// effective would tell an operator their change was live when it was not.
	applied config.EnforcementConfig
	source  string

	cancel context.CancelFunc
	done   chan struct{}
}

// Config controls where the watcher looks and how often.
type Config struct {
	Addr     string
	Password string
	DB       int
	PoolSize int
	Interval time.Duration
}

func NewWatcher(cfg Config, boot config.EnforcementConfig, apply Applier) *Watcher {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Watcher{
		client: redis.NewClient(&redis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
			PoolSize: cfg.PoolSize,
		}),
		interval: cfg.Interval,
		boot:     boot,
		apply:    apply,
		// Until a poll says otherwise, the file is what is running.
		applied: boot,
		source:  "file",
		done:    make(chan struct{}),
	}
}

// Start reads once, then keeps watching in the background.
func (w *Watcher) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	// One synchronous read, so a restart picks up an override that was already
	// in place instead of running the file settings for a whole interval. A
	// failure is logged and ignored: the gateway must start even if Redis is
	// down.
	first, done := context.WithTimeout(ctx, 2*time.Second)
	if err := w.poll(first); err != nil {
		log.Printf("[settings] initial read failed, running the settings from the file: %v", err)
	}
	done()

	// Publish what is actually in force, so the console shows the gateway's
	// truth rather than the last thing it asked for.
	w.publish(ctx)

	go w.loop(ctx)
}

func (w *Watcher) loop(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, w.interval)
			if err := w.poll(c); err != nil {
				log.Printf("[settings] read failed, keeping the settings in force: %v", err)
			} else {
				w.publish(c)
			}
			cancel()
		}
	}
}

// poll reads the override key and applies it if it has changed.
func (w *Watcher) poll(ctx context.Context) error {
	raw, err := w.client.Get(ctx, Key).Result()

	switch {
	case err == redis.Nil:
		// No override. Revert to the file settings, but only on the edge --
		// re-applying them every tick would be noise.
		if w.seen == "" {
			return nil
		}
		if applyErr := w.apply(w.boot); applyErr != nil {
			return applyErr
		}
		w.seen = ""
		w.applied, w.source = w.boot, "file"
		log.Printf("[settings] override cleared, back to the settings from the file")
		return nil

	case err != nil:
		return err
	}

	if raw == w.seen {
		return nil
	}

	// Recorded before the attempt, so a value that cannot be applied is not
	// re-parsed and re-logged on every tick. What is running is tracked
	// separately, and is only updated once an apply has actually succeeded.
	w.seen = raw

	next, err := Decode([]byte(raw), w.boot)
	if err != nil {
		log.Printf("[settings] override refused, keeping the settings in force: %v", err)
		return nil
	}

	if err := w.apply(next); err != nil {
		log.Printf("[settings] override refused, keeping the settings in force: %v", err)
		return nil
	}

	w.applied, w.source = next, "console"
	log.Printf("[settings] applied an override from the console")
	return nil
}

// publish writes what is currently in force to EffectiveKey.
//
// This is the gateway's answer to "what are you actually enforcing", and the
// console builds its form from it. It therefore reports the applied settings,
// never the requested ones: when an override has been refused, what is running
// is still the previous settings, and saying otherwise would be a lie the
// operator acts on.
func (w *Watcher) publish(ctx context.Context) {
	payload, err := json.Marshal(struct {
		Wire
		// Tells the console whether it is looking at the file or an override,
		// so it can offer "revert" only when there is something to revert.
		Source string `json:"source"`
	}{Wire: FromConfig(w.applied), Source: w.source})
	if err != nil {
		return
	}

	// A TTL so a stopped gateway stops advertising settings as current. Long
	// enough that a slow tick never lets it lapse.
	if err := w.client.Set(ctx, EffectiveKey, payload, 4*w.interval).Err(); err != nil {
		log.Printf("[settings] could not publish the effective settings: %v", err)
	}
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	if w == nil || w.cancel == nil {
		return nil
	}
	w.cancel()
	<-w.done
	return w.client.Close()
}
