package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Writer persists a security event. Redis implements this; Postgres can later.
type Writer interface {
	WriteEvent(ctx context.Context, ev Event) error
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.status = code
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.WriteHeader(http.StatusOK)
	}
	return sr.ResponseWriter.Write(b)
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware records one Event after detectors and the backend have run.
// Redis failures never change the client response.
func Middleware(writer Writer, collector *signals.Collector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if writer == nil {
				next.ServeHTTP(w, r)
				return
			}

			started := time.Now()
			requestID := newRequestID()
			// Set before the chain runs: request-scoped detectors label the
			// evidence they store with it, and the snapshot below asks for it
			// back by the same id.
			r.Header.Set(signals.RequestIDHeader, requestID)
			w.Header().Set(signals.RequestIDHeader, requestID)
			r = policy.AttachOutcome(r)

			body, _ := readBody(r)
			snippet := RedactSnippet(body)

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			ip := netutil.ClientIP(r)
			// Scoped to this request, not to the address. A blocked IP is
			// answered by the enforcer before the detectors run, so an
			// address-wide snapshot would report the attack that got it
			// blocked on every later request -- evidence the control plane
			// ingests as a fresh hit, keeping a campaign alive on traffic
			// nobody inspected.
			snap := collector.SnapshotFor(ip, requestID)
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}

			ev := Event{
				RequestID: requestID,
				Timestamp: time.Now().UTC(),
				IP:        ip,
				Method:    r.Method,
				Path:      r.URL.Path,
				Query:     RedactQuery(r.URL.RawQuery),
				Status:    status,
				UserAgent: truncate(r.UserAgent(), 256),
				Decision:  policy.Applied(r),
				RiskScore: snap.TotalScore,
				Fired:     uniqueFired(snap.Fired),
				Signals:   snap.Evidence,
				Snippet:   snippet,
				BackendMS: time.Since(started).Milliseconds(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			if err := writer.WriteEvent(ctx, ev); err != nil {
				log.Printf("redis telemetry write failed: %v", err)
			}
		})
	}
}

func uniqueFired(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("150405.000000")
	}
	return hex.EncodeToString(b[:])
}

// Unbounded on its own, and this runs above the enforcer -- so before
// proxy.BodyLimitMiddleware existed, an address the control plane had already
// blocked still had its whole body read here before the 403 was written. The
// cap is what makes this safe; it must stay ahead of this middleware.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, err
}
