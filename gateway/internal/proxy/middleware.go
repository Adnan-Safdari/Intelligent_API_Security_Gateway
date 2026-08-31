package proxy

import (
	"fmt"
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

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
