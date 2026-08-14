package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tag records the order middleware runs in.
func tag(order *[]string, name string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*order = append(*order, name)
			next.ServeHTTP(w, r)
		})
	}
}

// The listed order must be the execution order. The security chain depends on
// it: the IP resolver has to run before anything reads the client IP, and the
// enforcer before any detector spends work on a blocked address.
func TestChainRunsInListedOrder(t *testing.T) {
	var order []string

	handler := ChainMiddleware(
		tag(&order, "first"),
		tag(&order, "second"),
		tag(&order, "third"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	got := strings.Join(order, ",")
	if want := "first,second,third,handler"; got != want {
		t.Fatalf("order = %q, want %q", got, want)
	}
}

func TestChainWithNoMiddlewareCallsHandler(t *testing.T) {
	called := false
	handler := ChainMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Fatal("handler was not reached")
	}
}

// A middleware that short-circuits must stop everything after it.
func TestChainStopsAtShortCircuit(t *testing.T) {
	var order []string

	blocker := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "blocker")
			w.WriteHeader(http.StatusForbidden)
		})
	}

	handler := ChainMiddleware(
		tag(&order, "before"),
		blocker,
		tag(&order, "after"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got := strings.Join(order, ","); got != "before,blocker" {
		t.Fatalf("order = %q, want %q", got, "before,blocker")
	}
}

func TestRequestInspectionRestoresBody(t *testing.T) {
	const payload = `{"user":"pranav"}`

	var seen string
	handler := RequestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, len(payload))
		n, _ := r.Body.Read(buf)
		seen = string(buf[:n])
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(payload))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen != payload {
		t.Fatalf("handler saw %q, want the original body %q", seen, payload)
	}
}

func ExampleChainMiddleware() {
	logged := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("middleware")
			next.ServeHTTP(w, r)
		})
	}

	handler := ChainMiddleware(logged)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handler")
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	// Output:
	// middleware
	// handler
}
