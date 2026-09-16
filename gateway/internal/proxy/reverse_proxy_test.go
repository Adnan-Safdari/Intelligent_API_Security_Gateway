package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// seenBy returns a backend that reports the Host and X-Forwarded-Host it received.
func seenBy(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Host + "|" + r.Header.Get("X-Forwarded-Host")))
	}))
	t.Cleanup(backend.Close)
	return backend
}

func proxied(t *testing.T, cfg Config, prepare func(*http.Request)) (host, forwardedHost string) {
	t.Helper()
	cfg.ProxyTimeout = 5 * time.Second
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/api/products", nil)
	if prepare != nil {
		prepare(req)
	}
	rec := httptest.NewRecorder()
	NewReverseProxy(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	host, forwardedHost, _ = strings.Cut(rec.Body.String(), "|")
	return host, forwardedHost
}

// A backend that picks the site by Host -- a virtual host, a PaaS, a CDN --
// must be asked for itself, not for the gateway's public name.
func TestBackendReceivesItsOwnHost(t *testing.T) {
	backend := seenBy(t)
	host, forwarded := proxied(t, Config{BackendURL: backend.URL}, nil)

	if want := strings.TrimPrefix(backend.URL, "http://"); host != want {
		t.Errorf("Host = %q, want the backend's %q", host, want)
	}
	if forwarded != "api.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want the client's api.example.com", forwarded)
	}
}

func TestPreserveHostForwardsTheClientsHost(t *testing.T) {
	backend := seenBy(t)
	host, _ := proxied(t, Config{BackendURL: backend.URL, PreserveHost: true}, nil)

	if host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com", host)
	}
}

// Kept as sent, a forged X-Forwarded-Host would choose the hostname a backend
// writes into links it emails out.
func TestClientCannotChooseTheForwardedHost(t *testing.T) {
	backend := seenBy(t)
	_, forwarded := proxied(t, Config{BackendURL: backend.URL}, func(r *http.Request) {
		r.Header.Set("X-Forwarded-Host", "evil.example")
	})

	if forwarded != "api.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want api.example.com", forwarded)
	}
}
