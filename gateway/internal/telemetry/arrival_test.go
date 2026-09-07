package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type captureArrivals struct {
	mu   sync.Mutex
	recs []Arrival
}

func (c *captureArrivals) WriteEvent(_ context.Context, rec Arrival) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, rec)
	return nil
}

func (c *captureArrivals) all() []Arrival {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Arrival, len(c.recs))
	copy(out, c.recs)
	return out
}

func recorderFor(events Writer[Event], arrivals Writer[Arrival]) *Recorder {
	return &Recorder{Events: events, Arrivals: arrivals}
}

// The point of a separate arrival record: a request the gateway refused never
// reaches the backend, but it did arrive, and the window it arrived in has to
// count it. A refusal that produced no arrival would let an attacker lower
// their own request count by attacking hard enough to get blocked.
func TestARefusedRequestStillArrives(t *testing.T) {
	events, arrivals := &captureWriter{}, &captureArrivals{}
	refuse := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	handler := recorderFor(events, arrivals).Middleware(refuse)
	req := httptest.NewRequest(http.MethodGet, "/api/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got := arrivals.all()
	if len(got) != 1 {
		t.Fatalf("arrivals = %d, want 1", len(got))
	}
	if got[0].Path != "/api/login" || got[0].Method != http.MethodGet {
		t.Fatalf("arrival did not describe the request: %+v", got[0])
	}
	// The join key into the completion record, and the only thing tying the
	// two streams together.
	if got[0].RequestID == "" || got[0].RequestID != events.last().RequestID {
		t.Fatalf("arrival and event disagree on request id: %q vs %q",
			got[0].RequestID, events.last().RequestID)
	}
}

// A request still inside the chain has no completion record and may never get
// one. The arrival is the only evidence it exists, and the in-flight count is
// the only thing that says the window is unsettled rather than quiet.
func TestARequestInFlightIsAlreadyRecorded(t *testing.T) {
	arrivals := &captureArrivals{}
	rc := recorderFor(nil, arrivals)

	entered, release := make(chan struct{}), make(chan struct{})
	handler := rc.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))
	}()

	<-entered
	if got := arrivals.all(); len(got) != 1 {
		t.Fatalf("arrivals while in flight = %d, want 1", len(got))
	}
	if n := rc.InFlight(); n != 1 {
		t.Fatalf("in flight = %d, want 1", n)
	}

	close(release)
	<-done
	if n := rc.InFlight(); n != 0 {
		t.Fatalf("in flight after completion = %d, want 0", n)
	}
}

// Arrival time is not completion time, and the window assignment depends on
// the difference.
func TestArrivalIsStampedBeforeTheRequestRuns(t *testing.T) {
	events, arrivals := &captureWriter{}, &captureArrivals{}
	handler := recorderFor(events, arrivals).Middleware(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			time.Sleep(20 * time.Millisecond)
		}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))

	arrival := arrivals.all()[0]
	ev := events.last()
	if !ev.ArrivalTS.Equal(arrival.ArrivalTS) {
		t.Fatalf("event arrival %v does not match the arrival record %v", ev.ArrivalTS, arrival.ArrivalTS)
	}
	if !ev.Timestamp.After(ev.ArrivalTS) {
		t.Fatalf("completion %v is not after arrival %v", ev.Timestamp, ev.ArrivalTS)
	}
}

// Nil arrivals writer is the configuration with Redis off. It must not be a
// panic on the request path.
func TestArrivalsAreOptional(t *testing.T) {
	handler := recorderFor(nil, nil).Middleware(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// The arrival queue must behave like the event queue under back-pressure:
// drop, count, and never block the caller.
func TestArrivalQueueDropsRatherThanBlocking(t *testing.T) {
	blocked := &blockingArrivals{enter: make(chan struct{}, 1), release: make(chan struct{})}
	writer := NewNamedAsyncWriter[Arrival](blocked, 1, time.Minute, "arrivals")
	defer func() { close(blocked.release); writer.Close() }()

	if err := writer.WriteEvent(context.Background(), Arrival{}); err != nil {
		t.Fatal(err)
	}
	<-blocked.enter
	if err := writer.WriteEvent(context.Background(), Arrival{}); err != nil {
		t.Fatalf("one pending arrival should fit: %v", err)
	}
	if err := writer.WriteEvent(context.Background(), Arrival{}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue exceeded capacity: %v", err)
	}
	if writer.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", writer.Dropped())
	}
	if writer.Capacity() != 1 {
		t.Fatalf("capacity = %d, want 1", writer.Capacity())
	}
}

type blockingArrivals struct {
	enter   chan struct{}
	release chan struct{}
}

func (b *blockingArrivals) WriteEvent(context.Context, Arrival) error {
	b.enter <- struct{}{}
	<-b.release
	return nil
}
