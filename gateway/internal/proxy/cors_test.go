package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func writesStatus(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
}

func TestGatewayAnswerCORSAllowsAListedOrigin(t *testing.T) {
	h := GatewayAnswerCORS([]string{"http://localhost:5175"})(writesStatus(http.StatusUnauthorized))

	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	r.Header.Set("Origin", "http://localhost:5175")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5175" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the echoed origin", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin (echoing an origin, not *)", got)
	}
	if got := w.Header().Get("Access-Control-Expose-Headers"); got != "Retry-After" {
		t.Errorf("Access-Control-Expose-Headers = %q", got)
	}
}

func TestGatewayAnswerCORSRefusesAnUnlistedOrigin(t *testing.T) {
	h := GatewayAnswerCORS([]string{"http://localhost:5175"})(writesStatus(http.StatusUnauthorized))

	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("an unlisted origin got a CORS header: %q", got)
	}
}

func TestGatewayAnswerCORSWildcard(t *testing.T) {
	h := GatewayAnswerCORS([]string{"*"})(writesStatus(http.StatusUnauthorized))

	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	r.Header.Set("Origin", "http://anything.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := w.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q, want none for a wildcard allow", got)
	}
}

func TestGatewayAnswerCORSNeverOverridesTheBackendsOwnHeader(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What a backend's own CORS middleware would have already set before
		// the reverse proxy copies its response headers through.
		w.Header().Set("Access-Control-Allow-Origin", "https://backend-chose-this.example")
		w.WriteHeader(http.StatusOK)
	})
	h := GatewayAnswerCORS([]string{"*"})(backend)

	r := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	r.Header.Set("Origin", "http://localhost:5175")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://backend-chose-this.example" {
		t.Errorf("backend's own CORS header was overridden: %q", got)
	}
}

func TestGatewayAnswerCORSNoOriginHeaderIsUntouched(t *testing.T) {
	h := GatewayAnswerCORS([]string{"*"})(writesStatus(http.StatusUnauthorized))

	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a same-origin request (no Origin header) got a CORS header: %q", got)
	}
}

func TestGatewayAnswerCORSEmptyListIsANoOp(t *testing.T) {
	calledWith := (http.ResponseWriter)(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledWith = w
		w.WriteHeader(http.StatusUnauthorized)
	})
	h := GatewayAnswerCORS(nil)(inner)

	r := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	r.Header.Set("Origin", "http://localhost:5175")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("an empty allow-list added a CORS header: %q", got)
	}
	if _, wrapped := calledWith.(*corsAnswerWriter); wrapped {
		t.Error("an empty allow-list should skip the wrapper entirely, not just decline to act")
	}
}
