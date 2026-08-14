package signals

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// captureAlerts runs fn and returns whatever the detectors printed. The
// detectors report by writing to stdout, so that is what has to be inspected.
// The reader runs in its own goroutine so a burst of alerts cannot fill the
// pipe buffer and deadlock the test.
func captureAlerts(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = original
	return <-collected
}

// okBackend is a stand-in for the protected service.
func okBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend reached"))
	})
}

// probe sends one request through a middleware and reports the response.
func probe(handler http.Handler, method, target, ip, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = ip + ":54321"
	req.Header.Set("User-Agent", "test-agent/1.0")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// proxiedProbe sends a request that arrives from proxyIP but carries an
// X-Forwarded-For naming the real client behind it.
func proxiedProbe(handler http.Handler, target, proxyIP, clientIP string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = proxyIP + ":54321"
	req.Header.Set("X-Forwarded-For", clientIP)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func alertCount(output, marker string) int {
	return strings.Count(output, marker)
}
