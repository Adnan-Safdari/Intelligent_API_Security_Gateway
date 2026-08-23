package enforcement

import (
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Observer is the part of signals.Collector this package needs, named here so
// tests can supply evidence without standing up four detectors.
type Observer interface {
	SnapshotFor(ip, requestID string) signals.Snapshot
}

// Middleware watches what the detectors concluded about each request.
//
// It belongs outside every detector, but inside the policy enforcer. Most
// detectors record on the way in; response-aware detectors such as brute force
// record after next returns. Wrapping all of them makes this middleware's
// post-next snapshot run only after both kinds have finished.
//
// It only reads. Nothing here can refuse a request: the block it records
// applies from the caller's next request, and it is policy.Enforcer at the
// front of the chain that turns that into a response.
func Middleware(reflex *Reflex, collector Observer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Nothing to do and nothing to pay for when it is switched off.
		if !reflex.Active() || collector == nil {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)

			// After the handler, so this cannot delay the response. The
			// evidence is already recorded by the detectors either way.
			ip := netutil.ClientIP(r)
			reflex.Observe(ip, collector.SnapshotFor(ip, r.Header.Get(signals.RequestIDHeader)))
		})
	}
}
