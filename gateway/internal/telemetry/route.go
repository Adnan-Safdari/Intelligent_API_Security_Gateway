package telemetry

import (
	"fmt"
	"strings"
)

// UnmatchedRoute is what a path that matches no configured template records.
//
// It is a real category rather than an empty string, because "this client asked
// for things the application does not serve" is exactly what a scanner looks
// like, and treating it as missing data would throw that away.
const UnmatchedRoute = "<unmatched>"

// maxPathSegments bounds the work one request can cause. A path with more
// segments than any template could match is not worth walking -- without this,
// a request with ten thousand slashes would cost time proportional to the table
// on the request path.
const maxPathSegments = 24

// Table maps a request onto the route template it matched. Built once at boot
// and never mutated, so it needs no lock: route templates are structural, and
// changing one changes what previously recorded telemetry means, which is why
// they are deliberately not reconfigurable through the settings watcher.
type Table struct {
	routes []compiledRoute
}

type compiledRoute struct {
	method   string
	template string
	segments []segment
	// literals is the specificity score: how many segments are fixed text
	// rather than a wildcard.
	literals int
}

type segment struct {
	literal  string
	wildcard bool
}

// NewTable compiles route templates of the form "GET /api/products/{id}".
//
// An unparseable or ambiguous table is an error rather than a warning, and the
// gateway refuses to start on one. A route table that silently dropped half its
// entries would leave the telemetry quietly recording <unmatched> for real
// endpoints, and nothing downstream could tell that from a scanner.
func NewTable(templates []string) (*Table, error) {
	t := &Table{}
	seen := make(map[string]string, len(templates))

	for _, raw := range templates {
		method, path, err := splitTemplate(raw)
		if err != nil {
			return nil, err
		}

		segments, literals := compile(path)
		if len(segments) > maxPathSegments {
			return nil, fmt.Errorf(
				"route template %q has more than %d segments", raw, maxPathSegments)
		}

		// Two templates that differ only in wildcard *names* match exactly the
		// same requests, so one of them can never win. Caught here rather than
		// left to shadow the other silently.
		key := method + " " + shape(segments)
		if first, clash := seen[key]; clash {
			return nil, fmt.Errorf(
				"route templates %q and %q match the same requests", first, raw)
		}
		seen[key] = raw

		t.routes = append(t.routes, compiledRoute{
			method:   method,
			template: path,
			segments: segments,
			literals: literals,
		})
	}

	return t, nil
}

// Match answers with the template the request matched, or UnmatchedRoute.
//
// A nil Table answers UnmatchedRoute for everything, so a gateway configured
// without a route table records a consistent value rather than an empty one.
func (t *Table) Match(method, path string) string {
	if t == nil {
		return UnmatchedRoute
	}

	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > maxPathSegments {
		return UnmatchedRoute
	}

	// Specificity decides, not the order the templates were configured in.
	// /api/products/search must beat /api/products/{id} however the YAML is
	// written, because someone reordering a config file should not be able to
	// change what past telemetry means.
	best := ""
	bestLiterals := -1
	for _, route := range t.routes {
		if route.method != method || !route.matches(parts) {
			continue
		}
		if route.literals > bestLiterals {
			best, bestLiterals = route.template, route.literals
		}
	}

	if best == "" {
		return UnmatchedRoute
	}
	return best
}

func (r compiledRoute) matches(parts []string) bool {
	// Segment count first: it rejects almost everything for the cost of an
	// integer comparison.
	if len(parts) != len(r.segments) {
		return false
	}
	for i, seg := range r.segments {
		if seg.wildcard {
			// A wildcard stands for one segment, and an empty one means the
			// path had a doubled slash rather than a value.
			if parts[i] == "" {
				return false
			}
			continue
		}
		if parts[i] != seg.literal {
			return false
		}
	}
	return true
}

func splitTemplate(raw string) (method, path string, err error) {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return "", "", fmt.Errorf(
			"route template %q is not %q", raw, "METHOD /path")
	}

	method, path = strings.ToUpper(fields[0]), fields[1]
	if !strings.HasPrefix(path, "/") {
		return "", "", fmt.Errorf("route template %q path must start with /", raw)
	}
	return method, path, nil
}

func compile(path string) ([]segment, int) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	segments := make([]segment, 0, len(parts))
	literals := 0

	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			segments = append(segments, segment{wildcard: true})
			continue
		}
		segments = append(segments, segment{literal: part})
		literals++
	}

	return segments, literals
}

// shape renders a template with its wildcard names removed, so two templates
// that match the same requests produce the same string.
func shape(segments []segment) string {
	var b strings.Builder
	for _, seg := range segments {
		b.WriteByte('/')
		if seg.wildcard {
			b.WriteByte('*')
			continue
		}
		b.WriteString(seg.literal)
	}
	return b.String()
}
