package signals

import (
	"net/http"
	"strings"
	"testing"
)

const sqliMarker = "SQL INJECTION"

func sqliHandler() http.Handler {
	return NewSQLiDetector(DefaultSQLiDetectorConfig()).Middleware(okBackend())
}

func TestSQLiIgnoresCleanBody(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"email":"a@b.com","password":"hunter2"}`)
	})

	if strings.Contains(out, sqliMarker) {
		t.Fatalf("clean body raised an alert:\n%s", out)
	}
}

func TestSQLiDetectsSignatureInBody(t *testing.T) {
	for _, payload := range []string{
		`{"email":"' OR 1=1--"}`,
		`{"q":"UNION SELECT * FROM users"}`,
		`{"note":"-- comment"}`,
	} {
		out := captureAlerts(t, func() {
			probe(sqliHandler(), http.MethodPost, "/api/login", "203.0.113.5", payload)
		})

		if !strings.Contains(out, sqliMarker) {
			t.Errorf("payload %q went undetected", payload)
		}
	}
}

func TestSQLiMatchingIsCaseInsensitive(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"q":"union select"}`)
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("lowercase 'union select' should still match")
	}
}

func TestSQLiNeverBlocks(t *testing.T) {
	captureAlerts(t, func() {
		rec := probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"email":"' OR 1=1--"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d, detector must not block", rec.Code)
		}
		if rec.Body.String() != "backend reached" {
			t.Fatal("request never reached the backend")
		}
	})
}

// The detector reads the body, so it has to put it back for the proxy.
func TestSQLiRestoresBodyForBackend(t *testing.T) {
	const payload = `{"email":"' OR 1=1--","password":"x"}`

	var seen string
	handler := NewSQLiDetector(DefaultSQLiDetectorConfig()).Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, len(payload))
			n, _ := r.Body.Read(buf)
			seen = string(buf[:n])
			w.WriteHeader(http.StatusOK)
		}))

	captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/login", "203.0.113.5", payload)
	})

	if seen != payload {
		t.Fatalf("backend received %q, want the original body %q", seen, payload)
	}
}

func TestSQLiDisabledInspectsNothing(t *testing.T) {
	handler := NewSQLiDetector(SQLiDetectorConfig{Enabled: false}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/login", "203.0.113.5", `{"email":"' OR 1=1--"}`)
	})

	if strings.Contains(out, sqliMarker) {
		t.Fatal("a disabled detector alerted")
	}
}

func TestSQLiCustomPatternsReplaceDefaults(t *testing.T) {
	handler := NewSQLiDetector(SQLiDetectorConfig{
		Enabled:     true,
		SQLPatterns: []string{"DROP TABLE"},
	}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"drop table users"}`)
	})
	if !strings.Contains(out, sqliMarker) {
		t.Error("custom pattern did not match")
	}

	out = captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"' OR 1=1"}`)
	})
	if strings.Contains(out, sqliMarker) {
		t.Error("default patterns should not apply when custom ones are set")
	}
}

func TestSQLiEmptyPatternsFallBackToDefaults(t *testing.T) {
	handler := NewSQLiDetector(SQLiDetectorConfig{Enabled: true}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"' OR 1=1"}`)
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("an empty pattern list should fall back to the defaults")
	}
}

// Path, query, and body are all inspected. Injection through the query string
// used to be invisible; this pins the current behaviour.
func TestSQLiInspectsQueryString(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodGet, "/api/products?q=UNION%20SELECT", "203.0.113.5", "")
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("SQLi in the query string should be detected")
	}
}
