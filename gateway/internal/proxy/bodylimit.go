package proxy

import (
	"bytes"
	"io"
	"net/http"
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
// This has to run first. Every stage below it reads the whole body into memory
// -- telemetry snapshots it for the event record, the signal detectors scan it
// -- and telemetry sits *above* the enforcer in the chain, so an address the
// control plane had already blocked still had its body read in full before the
// 403 was written. Blocking an attacker therefore did nothing to stop them
// exhausting the process, which is the single thing enforcement exists to
// prevent. A cap is what stops it, and it only works above the first reader.
//
// The body is read once here and passed on as an in-memory buffer. The readers
// below already replaced r.Body with a buffer of their own, so in the ordinary
// case this adds no copy that was not happening anyway -- it makes the size of
// that copy something the gateway chose rather than something the client did.
func BodyLimitMiddleware(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxBytes <= 0 || r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}

			// Content-Length is a claim and not a fact, so it is worth testing
			// only because it lets an honest oversized upload be refused
			// without reading any of it. A lying or chunked request falls
			// through to the limited read below, which does not trust it.
			if r.ContentLength > maxBytes {
				refuseTooLarge(w)
				return
			}

			// One byte past the limit is what separates a body that is too long
			// from one that ends exactly on the limit and is still allowed.
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
			if err != nil {
				http.Error(w, "cannot read request body", http.StatusBadRequest)
				return
			}
			if int64(len(body)) > maxBytes {
				refuseTooLarge(w)
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

func refuseTooLarge(w http.ResponseWriter) {
	// Closed rather than kept alive: the rest of the body is still on the wire,
	// and draining it to make the connection reusable is exactly the work this
	// refusal exists to avoid doing.
	w.Header().Set("Connection", "close")
	http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
}
