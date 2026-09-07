package proxy

import (
	"reflect"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

func collectConfig() config.RedisConfig {
	return config.RedisConfig{
		Enabled:            true,
		Host:               "127.0.0.1",
		Port:               6379,
		TelemetryQueueSize: 8,
	}
}

// Every sink must be built when Redis is on. This is the guard, and it exists
// because of a bug that has already happened once: a config section dropped
// while wiring the server left a detector reading a zero config, switching
// itself off with nothing failing anywhere. A stream that is never written is
// the same failure -- the gateway serves traffic, the tests pass, and the
// records simply are not there.
//
// Walked by reflection so a sink added later is covered without anyone
// remembering to extend this.
func TestEveryTelemetrySinkIsWired(t *testing.T) {
	sinks := newTelemetrySinks(collectConfig())
	defer sinks.Close()

	v := reflect.ValueOf(sinks).Elem()
	typ := v.Type()
	checked := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		checked++
		if v.Field(i).IsZero() {
			t.Errorf("sink %s is nil with Redis enabled", field.Name)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d sinks inspected; the guard is not looking at anything", checked)
	}

	// The heartbeat reports on the queues the middleware actually writes to.
	// Pointed at anything else it would report a healthy idle queue while the
	// real one overflowed.
	// Compared as interfaces, since the heartbeat holds each queue through a
	// narrower one than the recorder does.
	if any(sinks.Heartbeat.Events) != any(sinks.Events) {
		t.Error("heartbeat reports on a different event queue from the recorder's")
	}
	if any(sinks.Heartbeat.Arrivals) != any(sinks.Arrivals) {
		t.Error("heartbeat reports on a different arrival queue from the recorder's")
	}
}

// Redis off is a supported configuration, not a degraded one. The gateway must
// still start: telemetry is diagnostic, and refusing to serve without a place
// to log would fail closed on the one component with no bearing on whether a
// request is safe.
func TestSinksAreEmptyWithoutRedis(t *testing.T) {
	sinks := newTelemetrySinks(config.RedisConfig{Enabled: false})
	defer sinks.Close()

	if sinks.Events != nil || sinks.Arrivals != nil || sinks.Heartbeat != nil {
		t.Fatalf("sinks built with Redis disabled: %+v", sinks)
	}
	// Close on empty sinks must not panic; Start defers it unconditionally.
	sinks.Close()
}
