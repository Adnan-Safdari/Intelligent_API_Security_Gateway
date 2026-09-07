package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// timedTransport measures the backend call and nothing else.
//
// The gateway used to report time.Since(started) from the top of the telemetry
// middleware as "backendMs", which is the whole chain -- logging, policy, the
// body cap, the body capture and all five detectors -- under a name that
// claimed otherwise. A detector that got slow looked exactly like a backend
// that got slow, and the anomaly features about to measure upstream latency
// would have been measuring the gateway's own cost.
//
// Measuring here is the only place the interval in the specification actually
// exists: from issuing the request to the backend until its response body has
// been read. httptrace could report connection and first-byte events but has
// no "body finished" hook, so it cannot express this definition.
type timedTransport struct {
	base http.RoundTripper
}

func (t *timedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// ReverseProxy clones the request but keeps the context, so this is the
	// same record the telemetry middleware attached.
	rec := telemetry.UpstreamOf(req)
	if rec == nil {
		return t.base.RoundTrip(req)
	}

	rec.Attempted = true
	start := time.Now()

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		// No status and no duration. A call that failed has neither, and
		// inventing them would put a measurement where there was none -- the
		// timeout would be indistinguishable from a fast backend error.
		rec.Outcome = classify(err)
		return nil, err
	}

	rec.Status, rec.HaveStatus = resp.StatusCode, true
	resp.Body = &timedBody{ReadCloser: resp.Body, rec: rec, start: start}
	return resp, nil
}

func classify(err error) string {
	// A cancelled context is the proxy timeout expiring in almost every case
	// that matters here; net.Error.Timeout covers the transport's own deadlines.
	var netErr interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return telemetry.OutcomeTimeout
	}
	return telemetry.OutcomeError
}

// timedBody stops the clock when the response body ends, which is what makes
// the recorded duration cover the whole backend response rather than just its
// headers.
type timedBody struct {
	io.ReadCloser
	rec   *telemetry.Upstream
	start time.Time
	bytes int64
	done  bool
}

func (b *timedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += int64(n)

	if err == io.EOF {
		b.finish(telemetry.OutcomeCompleted)
	} else if err != nil {
		b.finish(telemetry.OutcomeBodyIncomplete)
	}
	return n, err
}

func (b *timedBody) Close() error {
	// A body closed before it ended was cut short -- the client went away, or
	// the copy failed. It is not a completed response and must not be timed as
	// one, or an abandoned download would read as a very fast backend.
	b.finish(telemetry.OutcomeBodyIncomplete)
	return b.ReadCloser.Close()
}

func (b *timedBody) finish(outcome string) {
	if b.done {
		return
	}
	b.done = true

	b.rec.Outcome = outcome
	b.rec.ResponseBytes, b.rec.HaveResponseBytes = b.bytes, true

	// Only a response that actually finished gets a duration. An incomplete
	// one has a start and no end, which is not a measurement of anything.
	if outcome == telemetry.OutcomeCompleted {
		b.rec.DurationMS, b.rec.HaveDuration = time.Since(b.start).Milliseconds(), true
	}
}
