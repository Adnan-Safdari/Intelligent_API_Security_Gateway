package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// chain builds the pieces that matter for measuring the backend: telemetry on
// the outside, a slow detector in the middle, the reverse proxy at the bottom.
func chain(t *testing.T, backendURL string, detectorDelay time.Duration) (http.Handler, *captureWriter) {
	t.Helper()

	writer := &captureWriter{}
	slowDetector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(detectorDelay)
			next.ServeHTTP(w, r)
		})
	}

	handler := ChainMiddleware(
		telemetry.Middleware(writer, nil, nil),
		slowDetector,
	)(NewReverseProxy(Config{BackendURL: backendURL, ProxyTimeout: 5 * time.Second}))

	return handler, writer
}

type captureWriter struct{ events []telemetry.Event }

func (c *captureWriter) WriteEvent(_ context.Context, ev telemetry.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureWriter) last() telemetry.Event { return c.events[len(c.events)-1] }

// The test that would have caught the original mislabelling: backendMs used to
// be measured from outside every detector, so a slow detector was reported as
// a slow backend.
func TestBackendDurationExcludesTheGatewaysOwnWork(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, writer := chain(t, backend.URL, 150*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ev := writer.last()
	if ev.UpstreamDurationMS == nil {
		t.Fatal("a completed backend call recorded no duration")
	}

	// The backend slept 200ms and the detector 150ms. The upstream figure must
	// reflect only the former, and the whole-chain figure must include both.
	if d := *ev.UpstreamDurationMS; d < 150 || d > 350 {
		t.Errorf("upstreamDurationMs = %d, want roughly the backend's 200ms", d)
	}
	if *ev.UpstreamDurationMS >= ev.GatewayMS {
		t.Errorf("upstreamDurationMs %d is not less than gatewayMs %d; the detector's"+
			" delay leaked into the backend measurement",
			*ev.UpstreamDurationMS, ev.GatewayMS)
	}
	if ev.GatewayMS < 300 {
		t.Errorf("gatewayMs = %d, want the detector's 150ms plus the backend's 200ms",
			ev.GatewayMS)
	}
	if ev.BackendMS != *ev.UpstreamDurationMS {
		t.Errorf("backendMs = %d, want the true upstream duration %d",
			ev.BackendMS, *ev.UpstreamDurationMS)
	}
}

func TestCompletedCallIsRecordedAsBackendOrigin(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	handler, writer := chain(t, backend.URL, 0)

	req := httptest.NewRequest(http.MethodGet, "/api/nope", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ev := writer.last()
	if ev.ResponseOrigin != telemetry.OriginBackend {
		t.Errorf("responseOrigin = %q, want %q", ev.ResponseOrigin, telemetry.OriginBackend)
	}
	if ev.UpstreamStatus == nil || *ev.UpstreamStatus != http.StatusNotFound {
		t.Errorf("upstreamStatus = %v, want 404", ev.UpstreamStatus)
	}
	if ev.UpstreamOutcome != telemetry.OutcomeCompleted {
		t.Errorf("upstreamOutcome = %q, want %q", ev.UpstreamOutcome, telemetry.OutcomeCompleted)
	}
	if ev.GatewayReason != "" {
		t.Errorf("gatewayReason = %q, want empty for a backend answer", ev.GatewayReason)
	}
}

// A call that failed has no status and no duration. Inventing either would make
// a dead backend indistinguishable from a fast one.
func TestUnreachableBackendInventsNoMeasurement(t *testing.T) {
	// Nothing is listening here: the server is created and immediately closed.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	handler, writer := chain(t, deadURL, 0)

	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ev := writer.last()
	if ev.UpstreamStatus != nil {
		t.Errorf("upstreamStatus = %v, want null for a call that never answered", *ev.UpstreamStatus)
	}
	if ev.UpstreamDurationMS != nil {
		t.Errorf("upstreamDurationMs = %v, want null for a call that never answered",
			*ev.UpstreamDurationMS)
	}
	if !ev.UpstreamAttempted {
		t.Error("upstreamAttempted = false, but the gateway did try")
	}
	if ev.UpstreamOutcome != telemetry.OutcomeError && ev.UpstreamOutcome != telemetry.OutcomeTimeout {
		t.Errorf("upstreamOutcome = %q, want an error or a timeout", ev.UpstreamOutcome)
	}
	// ReverseProxy writes its own 502, so the status is the gateway's.
	if ev.ResponseOrigin != telemetry.OriginGateway {
		t.Errorf("responseOrigin = %q, want %q", ev.ResponseOrigin, telemetry.OriginGateway)
	}
}

// The case that cannot be inferred from decision and status: a 413 the body cap
// wrote looks exactly like a backend 413 without an explicit marker.
func TestBodyCapRefusalIsMarkedAsTheGatewaysOwn(t *testing.T) {
	writer := &captureWriter{}
	handler := ChainMiddleware(
		telemetry.Middleware(writer, nil, nil),
		BodyLimitMiddleware(16),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("an oversized body reached the backend")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(strings.Repeat("a", 64)))
	req.RemoteAddr = "203.0.113.5:54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}

	ev := writer.last()
	if ev.ResponseOrigin != telemetry.OriginGateway {
		t.Errorf("responseOrigin = %q, want %q", ev.ResponseOrigin, telemetry.OriginGateway)
	}
	if ev.GatewayReason != telemetry.ReasonBodyTooLarge {
		t.Errorf("gatewayReason = %q, want %q", ev.GatewayReason, telemetry.ReasonBodyTooLarge)
	}
	if ev.UpstreamAttempted {
		t.Error("upstreamAttempted = true, but the body cap refused before the backend")
	}
	if ev.RequestBodyBytes != nil {
		t.Errorf("requestBodyBytes = %v, want null: a refused body was never measured",
			*ev.RequestBodyBytes)
	}
}

// A confirmed empty body is a measured zero, which is a different observation
// from a body that could not be measured.
func TestConfirmedEmptyBodyIsAMeasuredZero(t *testing.T) {
	writer := &captureWriter{}
	handler := ChainMiddleware(
		telemetry.Middleware(writer, nil, nil),
		BodyLimitMiddleware(1024),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ev := writer.last()
	if ev.RequestBodyBytes == nil {
		t.Fatal("requestBodyBytes = null, want a measured 0 for a request with no body")
	}
	if *ev.RequestBodyBytes != 0 {
		t.Errorf("requestBodyBytes = %d, want 0", *ev.RequestBodyBytes)
	}
}

func TestMeasuredBodySizeIsRecorded(t *testing.T) {
	writer := &captureWriter{}
	handler := ChainMiddleware(
		telemetry.Middleware(writer, nil, nil),
		BodyLimitMiddleware(1024),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := strings.Repeat("x", 37)
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	ev := writer.last()
	if ev.RequestBodyBytes == nil || *ev.RequestBodyBytes != int64(len(body)) {
		t.Errorf("requestBodyBytes = %v, want %d", ev.RequestBodyBytes, len(body))
	}
}
