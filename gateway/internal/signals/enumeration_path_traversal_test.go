package signals

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

const (
	traversalMarker   = "PATH TRAVERSAL DETECTED"
	enumerationMarker = "ENUMERATION ATTACK DETECTED"
)

func traversalHandler() http.Handler {
	return NewTraversalEnumDetector(config.EnumerationConfig{Enabled: true}).Middleware(okBackend())
}

func TestTraversalIgnoresNormalPaths(t *testing.T) {
	out := captureAlerts(t, func() {
		for _, path := range []string{"/api/products", "/api/users/42", "/health"} {
			probe(traversalHandler(), http.MethodGet, path, "203.0.113.5", "")
		}
	})

	if strings.Contains(out, traversalMarker) || strings.Contains(out, enumerationMarker) {
		t.Fatalf("ordinary paths raised an alert:\n%s", out)
	}
}

func TestTraversalDetectedInQueryString(t *testing.T) {
	// Go decodes URL.Path, so the encoded signatures survive only in RawQuery.
	for _, target := range []string{
		"/api/file?path=../../etc/passwd",
		"/api/file?path=%2e%2e%2fsecret",
		"/api/file?path=..%2fsecret",
		"/api/file?path=%252e%252e%252fsecret",
	} {
		out := captureAlerts(t, func() {
			probe(traversalHandler(), http.MethodGet, target, "203.0.113.5", "")
		})

		if !strings.Contains(out, traversalMarker) {
			t.Errorf("target %q went undetected", target)
		}
	}
}

func TestTraversalDetectsDoubleEncodedPath(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(traversalHandler(), http.MethodGet, "/api/%252e%252e%252fsecret", "203.0.113.5", "")
	})

	if !strings.Contains(out, traversalMarker) {
		t.Fatal("double-encoded traversal path should be detected")
	}
}

func TestEnumerationDetectsSensitivePaths(t *testing.T) {
	for _, path := range []string{"/.env", "/.git/config", "/wp-admin", "/.ssh/id_rsa"} {
		out := captureAlerts(t, func() {
			probe(traversalHandler(), http.MethodGet, path, "203.0.113.5", "")
		})

		if !strings.Contains(out, enumerationMarker) {
			t.Errorf("path %q went undetected", path)
		}
	}
}

func TestEnumerationMatchingIsCaseInsensitive(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(traversalHandler(), http.MethodGet, "/WP-ADMIN", "203.0.113.5", "")
	})

	if !strings.Contains(out, enumerationMarker) {
		t.Fatal("uppercase /WP-ADMIN should still match")
	}
}

func TestTraversalNeverBlocks(t *testing.T) {
	captureAlerts(t, func() {
		rec := probe(traversalHandler(), http.MethodGet, "/api/file?path=../../etc/passwd",
			"203.0.113.5", "")

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d, detector must not block", rec.Code)
		}
		if rec.Body.String() != "backend reached" {
			t.Fatal("request never reached the backend")
		}
	})
}

func TestTraversalDisabledInspectsNothing(t *testing.T) {
	handler := NewTraversalEnumDetector(config.EnumerationConfig{Enabled: false}).
		Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodGet, "/.env", "203.0.113.5", "")
		probe(handler, http.MethodGet, "/api/f?p=../../etc/passwd", "203.0.113.5", "")
	})

	if strings.Contains(out, traversalMarker) || strings.Contains(out, enumerationMarker) {
		t.Fatal("a disabled detector alerted")
	}
}

func TestTraversalEmptyPatternsFallBackToDefaults(t *testing.T) {
	handler := NewTraversalEnumDetector(config.EnumerationConfig{Enabled: true}).
		Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodGet, "/.env", "203.0.113.5", "")
	})

	if !strings.Contains(out, enumerationMarker) {
		t.Fatal("empty pattern lists should fall back to the defaults")
	}
}

// One request can be both, and both should be reported rather than the first
// match winning.
func TestTraversalAndEnumerationReportedTogether(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(traversalHandler(), http.MethodGet, "/.git?path=../../etc/passwd", "203.0.113.5", "")
	})

	if !strings.Contains(out, traversalMarker) {
		t.Error("traversal not reported")
	}
	if !strings.Contains(out, enumerationMarker) {
		t.Error("enumeration not reported")
	}
}
