package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

var ErrQueueFull = errors.New("telemetry queue is full")

// AsyncWriter bounds both queued work and the time spent on one write. A slow
// Redis must lose telemetry instead of holding client requests or accumulating
// one goroutine per request until the gateway runs out of memory.
type AsyncWriter struct {
	writer   Writer
	queue    chan Event
	timeout  time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	close    sync.Once
	dropped  atomic.Uint64
	lastDrop atomic.Int64
}

func NewAsyncWriter(writer Writer, capacity int, timeout time.Duration) *AsyncWriter {
	if capacity < 1 {
		capacity = 1
	}
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &AsyncWriter{
		writer: writer, queue: make(chan Event, capacity), timeout: timeout,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *AsyncWriter) WriteEvent(ctx context.Context, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	select {
	case w.queue <- ev:
		return nil
	default:
		dropped := w.dropped.Add(1)
		// Overflow is most likely during an attack. Reporting its total once
		// per second avoids replacing an overloaded Redis with a log flood.
		now, last := time.Now().UnixNano(), w.lastDrop.Load()
		if now-last >= int64(time.Second) && w.lastDrop.CompareAndSwap(last, now) {
			slog.Warn("telemetry_queue_full", "dropped_total", dropped, "capacity", cap(w.queue))
		}
		return ErrQueueFull
	}
}

func (w *AsyncWriter) Dropped() uint64 { return w.dropped.Load() }

func (w *AsyncWriter) Close() {
	if w == nil {
		return
	}
	w.close.Do(w.cancel)
	<-w.done
}

func (w *AsyncWriter) run() {
	defer close(w.done)
	for {
		if w.ctx.Err() != nil {
			return
		}
		select {
		case <-w.ctx.Done():
			return
		case ev := <-w.queue:
			ctx, cancel := context.WithTimeout(w.ctx, w.timeout)
			err := w.writer.WriteEvent(ctx, ev)
			cancel()
			if err != nil && w.ctx.Err() == nil {
				slog.Warn("telemetry_write_failed", "error", err)
			}
		}
	}
}
