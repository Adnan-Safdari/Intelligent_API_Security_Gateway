package telemetry

import (
	"strings"
	"testing"
)

func mustTable(t *testing.T, templates ...string) *Table {
	t.Helper()
	table, err := NewTable(templates)
	if err != nil {
		t.Fatalf("NewTable(%v) = %v", templates, err)
	}
	return table
}

// The whole point of a template: resource identifiers vary constantly, and
// without this every one of them looks like a different endpoint.
func TestMatchCollapsesIdentifiersOntoOneTemplate(t *testing.T) {
	table := mustTable(t, "GET /api/products/{id}")

	for _, path := range []string{"/api/products/12", "/api/products/34"} {
		if got := table.Match("GET", path); got != "/api/products/{id}" {
			t.Errorf("Match(GET, %q) = %q, want the template", path, got)
		}
	}
}

// Specificity has to decide, not configuration order -- otherwise someone
// tidying the YAML changes what previously recorded telemetry means.
func TestLiteralBeatsWildcardWhicheverOrderTheyAreConfigured(t *testing.T) {
	orders := [][]string{
		{"GET /api/products/search", "GET /api/products/{id}"},
		{"GET /api/products/{id}", "GET /api/products/search"},
	}

	for _, templates := range orders {
		table := mustTable(t, templates...)

		if got := table.Match("GET", "/api/products/search"); got != "/api/products/search" {
			t.Errorf("order %v: Match(/api/products/search) = %q, want the literal",
				templates, got)
		}
		if got := table.Match("GET", "/api/products/12"); got != "/api/products/{id}" {
			t.Errorf("order %v: Match(/api/products/12) = %q, want the wildcard",
				templates, got)
		}
	}
}

func TestMethodIsPartOfTheMatch(t *testing.T) {
	table := mustTable(t, "POST /api/login")

	if got := table.Match("GET", "/api/login"); got != UnmatchedRoute {
		t.Errorf("Match(GET, /api/login) = %q, want %q", got, UnmatchedRoute)
	}
	if got := table.Match("POST", "/api/login"); got != "/api/login" {
		t.Errorf("Match(POST, /api/login) = %q, want the template", got)
	}
}

// An unserved path is a real category, not missing data: it is what a scanner
// walking the application looks like.
func TestUnservedPathIsACategoryNotAnEmptyString(t *testing.T) {
	table := mustTable(t, "GET /api/products")

	for _, path := range []string{"/wp-admin", "/.git/config", "/api/products/12/reviews"} {
		if got := table.Match("GET", path); got != UnmatchedRoute {
			t.Errorf("Match(GET, %q) = %q, want %q", path, got, UnmatchedRoute)
		}
	}
}

// A pathological path must not cost time proportional to how long it is.
func TestAbsurdlyDeepPathIsBounded(t *testing.T) {
	table := mustTable(t, "GET /api/products/{id}")
	deep := "/" + strings.Repeat("a/", 5000)

	if got := table.Match("GET", deep); got != UnmatchedRoute {
		t.Errorf("Match on a %d-segment path = %q, want %q", 5000, got, UnmatchedRoute)
	}
}

// Traversal segments must survive to the recorded path. Collapsing them would
// erase exactly the behaviour the traversal detector exists to catch, and the
// anomaly features measure path diversity on this value.
func TestTraversalSegmentsAreNotCollapsedIntoAMatch(t *testing.T) {
	table := mustTable(t, "GET /api/products/{id}")

	// /api/../../etc/passwd must not be quietly resolved to something that
	// matches a real template.
	if got := table.Match("GET", "/api/../../etc/passwd"); got != UnmatchedRoute {
		t.Errorf("a traversal path matched %q; it must stay %q", got, UnmatchedRoute)
	}
}

// A wildcard stands for a value. A doubled slash has none.
func TestWildcardDoesNotMatchAnEmptySegment(t *testing.T) {
	table := mustTable(t, "GET /api/products/{id}")

	if got := table.Match("GET", "/api/products/"); got != UnmatchedRoute {
		t.Errorf("Match(/api/products/) = %q, want %q", got, UnmatchedRoute)
	}
}

// A nil table has to answer consistently rather than with an empty string, so
// a gateway with no route table still produces a usable column.
func TestNilTableAnswersUnmatched(t *testing.T) {
	var table *Table

	if got := table.Match("GET", "/api/products"); got != UnmatchedRoute {
		t.Errorf("nil table Match = %q, want %q", got, UnmatchedRoute)
	}
}

// Two templates matching the same requests means one can never win. Better to
// refuse at boot than to shadow one silently.
func TestAmbiguousTableIsRefusedAtBoot(t *testing.T) {
	_, err := NewTable([]string{"GET /api/products/{id}", "GET /api/products/{slug}"})
	if err == nil {
		t.Fatal("NewTable accepted two templates that match the same requests")
	}
}

func TestMalformedTemplatesAreRefusedAtBoot(t *testing.T) {
	for _, bad := range []string{
		"/api/products",    // no method
		"GET api/products", // path does not start with /
		"GET /a /b",        // too many fields
		"",                 // empty
	} {
		if _, err := NewTable([]string{bad}); err == nil {
			t.Errorf("NewTable(%q) was accepted, want an error", bad)
		}
	}
}

// The gateway must not start on a table that would silently record <unmatched>
// for a real endpoint.
func TestOverlongTemplateIsRefusedAtBoot(t *testing.T) {
	long := "GET /" + strings.Repeat("a/", maxPathSegments+1)

	if _, err := NewTable([]string{long}); err == nil {
		t.Error("NewTable accepted a template longer than the segment bound")
	}
}
