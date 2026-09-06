package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Writer accepts a security event for storage. Production uses AsyncWriter so
// persistence never holds the client connection open.
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
	if !sr.wrote {
		sr.WriteHeader(http.StatusOK)
	}
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter { return sr.ResponseWriter }

type bodyCaptureKey struct{}

type bodyCapture struct {
	snippet string
}

// Middleware records one Event after detectors and the backend have run.
// Redis failures never change the client response.
//
// routes may be nil, in which case every request records UnmatchedRoute. That
// is a usable answer rather than an empty one, so a gateway configured without
// a route table still produces a consistent column.
func Middleware(writer Writer, collector *signals.Collector, routes *Table, auth *AuthOutcomes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			requestID := newRequestID()
			// Set before the chain runs: request-scoped detectors label the
			// evidence they store with it, and the snapshot below asks for it
			// back by the same id.
			r.Header.Set(signals.RequestIDHeader, requestID)
			w.Header().Set(signals.RequestIDHeader, requestID)
			r = policy.AttachOutcome(r)
			// Attached before anything below it runs: the body cap, the policy
			// enforcer and the transport all fill this in as the request
			// travels, and it is read once after the chain returns.
			r, upstream := AttachUpstream(r)
			capture := &bodyCapture{}
			if writer != nil {
				r = r.WithContext(context.WithValue(r.Context(), bodyCaptureKey{}, capture))
			}

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			match := policy.Matched(r)
			if match != nil {
				slog.InfoContext(r.Context(), "policy_match",
					"request_id", requestID, "action", match.Action, "policy_source", match.Source,
					"client_ip", match.ClientIP, "route", match.Route, "method", match.Method,
					"requests_per_minute", match.RequestsPerMinute, "reason", match.Reason,
					"outcome", match.Outcome, "status", rec.status,
				)
			}
			if writer == nil {
				return
			}

			// A policy refusal is already fully described by the decision, so
			// it is mapped here rather than recorded by the enforcer. The
			// body-cap refusals are not, which is why those set it themselves.
			if upstream.GatewayReason == "" {
				upstream.GatewayReason = gatewayReasonFor(policy.Applied(r))
			}

			routeTemplate := routes.Match(r.Method, r.URL.Path)

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
				// Recorded exactly as Go produced it: not lexically cleaned, so
				// a traversal probe's ../ segments survive into the record.
				// Collapsing them here would erase the behaviour the traversal
				// detector exists to catch, and the anomaly features measure
				// path diversity on this value.
				Path:          r.URL.Path,
				RouteTemplate: routeTemplate,
				Query:         RedactQuery(r.URL.RawQuery),
				Status:        status,
				UserAgent:     truncate(r.UserAgent(), 256),
				Decision:      policy.Applied(r),
				Policy:        match,
				RiskScore:     snap.TotalScore,
				Fired:         uniqueFired(snap.Fired),
				Signals:       snap.Evidence,
				Snippet:       capture.snippet,

				ResponseOrigin:    upstream.Origin(),
				GatewayReason:     upstream.GatewayReason,
				UpstreamAttempted: upstream.Attempted,
				UpstreamOutcome:   upstream.Outcome,

				UpstreamStatus:     optionalInt(upstream.Status, upstream.HaveStatus),
				UpstreamDurationMS: optionalInt64(upstream.DurationMS, upstream.HaveDuration),
				ResponseBodyBytes:  optionalInt64(upstream.ResponseBytes, upstream.HaveResponseBytes),
				RequestBodyBytes:   optionalInt64(upstream.BodyBytes, upstream.BodyMeasured),

				// Read from the backend's status, never the one the client
				// saw: a login the enforcer answered with a 403 says nothing
				// about the password.
				LoginAttempt: auth.IsLogin(r.Method, routeTemplate),
				AuthOutcome: auth.Outcome(
					r.Method, routeTemplate, upstream.Status, upstream.HaveStatus),

				BackendMS: upstream.DurationMS,
				GatewayMS: time.Since(started).Milliseconds(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			if err := writer.WriteEvent(ctx, ev); err != nil && !errors.Is(err, ErrQueueFull) {
				log.Printf("redis telemetry write failed: %v", err)
			}
		})
	}
}

// CaptureBody belongs after policy enforcement and the body-size guard. Keeping
// it separate from the outer event recorder lets refusals produce telemetry
// without first consuming an attacker-controlled request body.
func CaptureBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture, ok := r.Context().Value(bodyCaptureKey{}).(*bodyCapture); ok {
			body, err := readBody(r)
			if err != nil {
				RecordGatewayAnswer(r, ReasonBodyUnreadable)
				http.Error(w, "cannot read request body", http.StatusBadRequest)
				return
			}
			capture.snippet = RedactSnippet(body)
		}
		next.ServeHTTP(w, r)
	})
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

// The body-size guard must precede CaptureBody so telemetry only buffers data
// that has already passed the configured cap.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, err
}
