package telemetry

import (
	"context"
	"time"
)

// Health is one heartbeat from the gateway's telemetry path.
//
// One stream, appended to once a second, answers three questions adaptive
// baseline learning needs and that no per-request record can:
//
//   - Was telemetry lost in this window? The drop counters are process-wide
//     and monotonic, so a delta across the window says so. It is deliberately
//     not attributable to one address -- a dropped record carries no identity
//     by definition -- which is why the quality flag it feeds is window-wide.
//   - Was the whole interval observed? Sixty consecutive Seq values say the
//     gateway was up for all of it. A gap says a window is short through no
//     fault of the traffic in it, which otherwise reads as a quiet minute.
//   - How many requests were still in flight? A window whose requests have
//     not settled yet is incomplete rather than sparse.
//
// The cost is one Redis append per second, off the request path entirely.
type Health struct {
	// Seq counts heartbeats since this process started. It restarts at 1 on
	// a restart, which is the point: the gap is what marks the outage.
	Seq int64     `json:"seq"`
	At  time.Time `json:"at"`

	DroppedTotal         uint64 `json:"droppedTotal"`
	ArrivalsDroppedTotal uint64 `json:"arrivalsDroppedTotal"`

	InFlight int64 `json:"inFlight"`

	// QueueLen against QueueCap is the warning the drop counter cannot give:
	// a queue sitting near capacity is about to lose records, where a drop
	// total only reports loss that already happened.
	QueueCap int `json:"queueCap"`
	QueueLen int `json:"queueLen"`

	ArrivalQueueCap int `json:"arrivalQueueCap"`
	ArrivalQueueLen int `json:"arrivalQueueLen"`
}

// QueueStats is the part of AsyncWriter the heartbeat reads. Taking an
// interface rather than the concrete writer keeps the heartbeat testable
// without a Redis, and keeps it from reaching into queue internals.
type QueueStats interface {
	Dropped() uint64
	Depth() int
	Capacity() int
}

// InFlightSource is the running request count, maintained by Recorder.
type InFlightSource interface {
	InFlight() int64
}

// Heartbeat appends one Health record per interval until stop is closed.
//
// Every input is optional. A gateway with no arrivals queue still reports its
// event queue; one with neither still emits the sequence, because the sequence
// alone answers "was the gateway up for this whole window".
type Heartbeat struct {
	Writer   Writer[Health]
	Events   QueueStats
	Arrivals QueueStats
	Requests InFlightSource
	Interval time.Duration
}

// Start runs the heartbeat until stop is closed. It returns immediately.
func (h *Heartbeat) Start(stop <-chan struct{}) {
	if h == nil || h.Writer == nil {
		return
	}
	interval := h.Interval
	if interval <= 0 {
		interval = time.Second
	}
	go h.run(stop, interval)
}

func (h *Heartbeat) run(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var seq int64
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			seq++
			// Bounded like every other telemetry write, and on its own
			// context: a heartbeat that hung would stop reporting the
			// overload it exists to report.
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			_ = h.Writer.WriteEvent(ctx, h.sample(seq, now))
			cancel()
		}
	}
}

func (h *Heartbeat) sample(seq int64, now time.Time) Health {
	rec := Health{Seq: seq, At: now.UTC()}
	if h.Events != nil {
		rec.DroppedTotal = h.Events.Dropped()
		rec.QueueCap = h.Events.Capacity()
		rec.QueueLen = h.Events.Depth()
	}
	if h.Arrivals != nil {
		rec.ArrivalsDroppedTotal = h.Arrivals.Dropped()
		rec.ArrivalQueueCap = h.Arrivals.Capacity()
		rec.ArrivalQueueLen = h.Arrivals.Depth()
	}
	if h.Requests != nil {
		rec.InFlight = h.Requests.InFlight()
	}
	return rec
}
