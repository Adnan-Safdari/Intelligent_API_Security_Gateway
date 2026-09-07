package proxy

import (
	"bytes"
	"io"
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// DefaultMaxBodyBytes is the cap applied when the config does not name one.
//
// The backend this fronts accepts JSON logins, searches and cart updates, none
// of which reach a megabyte. Erring high costs a megabyte of headroom per
// in-flight request; erring low breaks a legitimate upload, so the number is
// picked to be uninteresting rather than tight.
const DefaultMaxBodyBytes int64 = 1 << 20

// BodyLimitMiddleware refuses a request whose body is larger than maxBytes, and
// buffers anything smaller so no later stage can be made to allocate without
// bound.
//
// This must run before any body reader, but after policy enforcement. A request
// already refused by policy needs no body read at all; accepted requests still
// need a cap before telemetry or detectors can allocate a full body buffer.
//
// The body is read once here and passed on as an in-memory buffer. The readers
// below already replaced r.Body with a buffer of their own, so in the ordinary
// case this adds no copy that was not happening anyway -- it makes the size of
// that copy something the gateway chose rather than something the client did.
func BodyLimitMiddleware(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes <= 0 || r.Body == nil || r.Body == http.NoBody {
				// A request that definitely carried no body is a measured
				// zero, not an unknown. The distinction is the whole point of
				// the field: a mean over body sizes must count this and must
				// not count a body that was refused unread.
				if r.Body == nil || r.Body == http.NoBody {
					telemetry.RecordBodySize(r, 0)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Content-Length is a claim and not a fact, so it is worth testing
			// only because it lets an honest oversized upload be refused
			// without reading any of it. A lying or chunked request falls
			// through to the limited read below, which does not trust it.
			if r.ContentLength > maxBytes {
				refuseTooLarge(w, r)
				return
			}

			// One byte past the limit is what separates a body that is too long
			// from one that ends exactly on the limit and is still allowed.
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
			if err != nil {
				telemetry.RecordGatewayAnswer(r, telemetry.ReasonBodyUnreadable)
				http.Error(w, "cannot read request body", http.StatusBadRequest)
				return
			}
			if int64(len(body)) > maxBytes {
				refuseTooLarge(w, r)
				return
			}

			// The size was already computed to make the decision above; it was
			// previously thrown away.
			telemetry.RecordBodySize(r, int64(len(body)))
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

func refuseTooLarge(w http.ResponseWriter, r *http.Request) {
	// The body was never read, so its size is unknown rather than zero, and
	// this status is the gateway's own rather than anything the backend said.
	telemetry.RecordGatewayAnswer(r, telemetry.ReasonBodyTooLarge)

	// Closed rather than kept alive: the rest of the body is still on the wire,
	// and draining it to make the connection reusable is exactly the work this
	// refusal exists to avoid doing.
	w.Header().Set("Connection", "close")
	http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
}
