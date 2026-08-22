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

	// The raw JSON last applied, so an unchanged key is not re-applied every
	// tick and the log stays quiet when nothing is happening. The empty string
	// means "currently running the boot settings".
	last string

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
		done:     make(chan struct{}),
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
		if w.last == "" {
			return nil
		}
		if applyErr := w.apply(w.boot); applyErr != nil {
			return applyErr
		}
		w.last = ""
		log.Printf("[settings] override cleared, back to the settings from the file")
		return nil

	case err != nil:
		return err
	}

	if raw == w.last {
		return nil
	}

	next, err := Decode([]byte(raw), w.boot)
	if err != nil {
		// A bad override is refused and reported, and the gateway keeps
		// running what it has. Storing it as last stops the same broken value
		// being re-parsed and re-logged every interval.
		w.last = raw
		log.Printf("[settings] override refused, keeping the settings in force: %v", err)
		return nil
	}

	if err := w.apply(next); err != nil {
		w.last = raw
		log.Printf("[settings] override refused, keeping the settings in force: %v", err)
		return nil
	}

	w.last = raw
	log.Printf("[settings] applied an override from the console")
	return nil
}

// publish writes what is currently in force to EffectiveKey.
func (w *Watcher) publish(ctx context.Context) {
	current := w.boot
	if w.last != "" {
		// Best effort: if the stored override no longer parses, the boot
		// settings are what is running anyway.
		if decoded, err := Decode([]byte(w.last), w.boot); err == nil {
			current = decoded
		}
	}

	payload, err := json.Marshal(struct {
		Wire
		// Tells the console whether it is looking at the file or an override,
		// so it can offer "revert" only when there is something to revert.
		Source string `json:"source"`
	}{Wire: FromConfig(current), Source: sourceOf(w.last)})
	if err != nil {
		return
	}

	// A TTL so a stopped gateway stops advertising settings as current. Long
	// enough that a slow tick never lets it lapse.
	if err := w.client.Set(ctx, EffectiveKey, payload, 4*w.interval).Err(); err != nil {
		log.Printf("[settings] could not publish the effective settings: %v", err)
	}
}

func sourceOf(last string) string {
	if last == "" {
		return "file"
	}
	return "console"
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
