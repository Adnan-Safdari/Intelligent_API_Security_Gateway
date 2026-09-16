package proxy

import (
	"fmt"
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// LivenessPath is answered by the gateway itself rather than proxied. It is
// deliberately not /api/health: the gateway forwards every path it serves, so
// anything it answers on its own shadows a route the backend could legitimately
// want, and this prefix is one no application would claim.
const LivenessPath = "/__iasg/alive"

// WithLiveness answers the container's liveness probe in front of the
// middleware chain.
//
// Docker polls this every thirty seconds for the lifetime of the container.
// Routed through the chain it would be proxied to the backend, shown to every
// detector and recorded as a client request, which is traffic nobody sent
// appearing in evidence that is supposed to describe real clients. Answering
// here keeps the probe meaningful -- it still proves the HTTP server is
// serving, not merely that the port is bound -- while keeping it out of the
// request path entirely.
func WithLiveness(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == LivenessPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Middleware func(http.Handler) http.Handler

func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func LoggingMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := netutil.ClientIP(r)

		fmt.Println("------ Incoming Request ------")
		fmt.Println("Method:", r.Method)
		fmt.Println("Path:", r.URL.Path)
		fmt.Println("IP:", ip)
		fmt.Println("User-Agent:", r.UserAgent())

		next.ServeHTTP(w, r)
	})
}

// RequestInspectionMiddleware is deliberately gone. It printed every header and
// the raw request body to stdout for every request, which put passwords and
// tokens in the logs -- the exact disclosure telemetry/redact.go exists to
// prevent, undone one middleware later. It also read the body a second time
// with no limit. Neither is worth keeping for a debug printer; use the recorded
// event, which is redacted.
