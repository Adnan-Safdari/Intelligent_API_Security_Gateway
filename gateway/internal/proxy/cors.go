package proxy

import "net/http"

// GatewayAnswerCORS lets a browser read a response the gateway wrote itself --
// an ownership-guard refusal, a policy block, a body-size rejection -- none of
// which ever reach the backend's own CORS middleware. Without this, a
// cross-origin fetch() sees such a refusal only as an opaque network error:
// the same failure mode as the backend being unreachable, which is exactly
// the wrong thing to show for "your request was blocked."
//
// It never touches a response the backend answered: those already carry
// whatever CORS policy the backend chose, and this defers to it by checking
// for an existing Access-Control-Allow-Origin header before acting. An empty
// allow-list is a no-op, so a gateway that never sets cors_allowed_origins
// behaves exactly as before this middleware existed.
func GatewayAnswerCORS(allowed []string) Middleware {
	allowAny := false
	set := make(map[string]struct{}, len(allowed))
	for _, origin := range allowed {
		if origin == "*" {
			allowAny = true
			continue
		}
		set[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			// Nothing configured: skip the wrapper entirely rather than wrap
			// every response in a writer that would never act.
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			_, listed := set[origin]
			if !allowAny && !listed {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(&corsAnswerWriter{ResponseWriter: w, origin: origin, allowAny: allowAny}, r)
		})
	}
}

// corsAnswerWriter adds the CORS header the first time headers are sent, and
// only when the wrapped handler has not already set one -- a backend answer
// proxied straight through must never be second-guessed here.
type corsAnswerWriter struct {
	http.ResponseWriter
	origin     string
	allowAny   bool
	headerSent bool
}

func (w *corsAnswerWriter) WriteHeader(status int) {
	w.apply()
	w.ResponseWriter.WriteHeader(status)
}

func (w *corsAnswerWriter) Write(p []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(p)
}

func (w *corsAnswerWriter) apply() {
	if w.headerSent {
		return
	}
	w.headerSent = true
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		return
	}
	if w.allowAny {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", w.origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
}

// Flush keeps the reverse proxy's streamed responses working through this
// wrapper, the same reason heldResponse (internal/ownership) implements it.
func (w *corsAnswerWriter) Flush() {
	w.apply()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
