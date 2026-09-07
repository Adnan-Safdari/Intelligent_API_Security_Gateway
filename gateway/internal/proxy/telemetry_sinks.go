package proxy

import (
	"log"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	redisstore "github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/storage/redis"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// telemetrySinks is everywhere the gateway writes telemetry, built together.
//
// Separate from Start for the same reason Config.Enforcement() is separate:
// this is a place where forgetting one field switches a whole stream off with
// nothing failing and no error anywhere. A test can call this; it cannot call
// the middle of Start.
type telemetrySinks struct {
	Events    telemetry.Writer[telemetry.Event]
	Arrivals  telemetry.Writer[telemetry.Arrival]
	Heartbeat *telemetry.Heartbeat

	closers []func()
}

// newTelemetrySinks returns empty sinks when Redis is off or unreachable. The
// gateway runs either way -- telemetry is diagnostic, and a gateway that
// refused to start without somewhere to log would fail closed on the one
// component that has no bearing on whether a request is safe.
func newTelemetrySinks(cfg config.RedisConfig) *telemetrySinks {
	sinks := &telemetrySinks{}
	if !cfg.Enabled {
		return sinks
	}
	store, err := redisstore.New(cfg)
	if err != nil {
		log.Printf("Redis telemetry disabled: %v", err)
		return sinks
	}
	sinks.closers = append(sinks.closers, func() { _ = store.Close() })

	queue, timeout := cfg.TelemetryQueueSize, cfg.TelemetryWriteTimeout
	events := telemetry.NewNamedAsyncWriter[telemetry.Event](store, queue, timeout, "telemetry")

	// Its own queue, not a share of the events queue. Arrivals are written
	// before the backend is called and completions after, so one queue would
	// let a slow backend's completions crowd out the arrivals of the requests
	// still waiting on it -- losing exactly the records that prove those
	// requests existed.
	arrivals := telemetry.NewNamedAsyncWriter[telemetry.Arrival](
		store.Arrivals(cfg), queue, timeout, "arrivals")

	sinks.closers = append(sinks.closers, events.Close, arrivals.Close)
	sinks.Events, sinks.Arrivals = events, arrivals
	sinks.Heartbeat = &telemetry.Heartbeat{
		Writer:   store.Health(cfg),
		Events:   events,
		Arrivals: arrivals,
	}
	return sinks
}

// Close shuts the writers down before the connection they write over.
func (t *telemetrySinks) Close() {
	for i := len(t.closers) - 1; i >= 0; i-- {
		t.closers[i]()
	}
}
