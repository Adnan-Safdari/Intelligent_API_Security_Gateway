package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The property the whole middleware exists for: nothing downstream is ever
// handed more bytes than the gateway agreed to hold.
func TestOversizedBodyNeverReachesTheNextStage(t *testing.T) {
	reached := false
	handler := BodyLimitMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(strings.Repeat("A", 4096)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Fatal("an oversized body was passed to the next handler")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// A body that lies about its length is the case the Content-Length shortcut
// cannot answer, so the read itself has to be the thing that stops.
func TestALyingContentLengthIsStillCapped(t *testing.T) {
	handler := BodyLimitMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("an oversized body was passed to the next handler")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(strings.Repeat("A", 4096)))
	// What a hostile client controls: the claim, not the content.
	req.ContentLength = 8
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// Carried over from the middleware this replaced: every stage below re-reads
// the body, so passing it on unread would break the detectors and the proxy.
func TestAnAllowedBodyIsPassedOnIntact(t *testing.T) {
	const payload = `{"user":"pranav"}`

	var seen string
	handler := BodyLimitMiddleware(DefaultMaxBodyBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = string(body)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(payload))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen != payload {
		t.Fatalf("handler saw %q, want the original body %q", seen, payload)
	}
}

// The limit is a maximum, not a target: a body landing exactly on it is a
// legitimate request and refusing it would be an off-by-one outage.
func TestABodyExactlyOnTheLimitIsAllowed(t *testing.T) {
	payload := strings.Repeat("A", 64)

	var seen int
	handler := BodyLimitMiddleware(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = len(body)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(payload)))

	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatal("a body exactly on the limit was refused")
	}
	if seen != 64 {
		t.Fatalf("handler saw %d bytes, want 64", seen)
	}
}

// A GET carries no body and must not be turned into a 413 or a bad request.
func TestARequestWithNoBodyPassesThrough(t *testing.T) {
	reached := false
	handler := BodyLimitMiddleware(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/products", nil))

	if !reached {
		t.Fatal("a bodyless request was refused")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
