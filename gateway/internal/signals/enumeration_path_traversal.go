package signals

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

func DefaultTraversalPatterns() []string {
	return []string{
		"../",
		"..\\",
		"%2e%2e%2f",
		"%2e%2e/",
		"..%2f",
		"%2e%2e%5c",
	}
}

func DefaultEnumerationPatterns() []string {
	return []string{
		"/.env",
		"/.git",
		"/.aws",
		"/wp-admin",
		"/etc/passwd",
		"/.bash_history",
		"/.ssh",
	}
}

// TraversalEnumDetector inspects URLs for path traversal and enumeration patterns.
type TraversalEnumDetector struct {
	enabled             bool
	traversalPatterns   []string
	enumerationPatterns []string
	last                *lastEvidenceStore
}

func NewTraversalEnumDetector(cfg config.EnumerationConfig) *TraversalEnumDetector {
	traversal := cfg.TraversalPatterns
	if len(traversal) == 0 {
		traversal = DefaultTraversalPatterns()
	}
	enumeration := cfg.EnumerationPatterns
	if len(enumeration) == 0 {
		enumeration = DefaultEnumerationPatterns()
	}

	return &TraversalEnumDetector{
		enabled:             cfg.Enabled,
		traversalPatterns:   traversal,
		enumerationPatterns: enumeration,
		last:                newLastEvidenceStore(lastEvidenceTTL),
	}
}

func (ted *TraversalEnumDetector) Name() string { return SignalTraversal }

func (ted *TraversalEnumDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ted.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		path := r.URL.Path
		query := r.URL.RawQuery
		traversalHits := findPatternHits(path+" "+query, ted.traversalPatterns)
		enumHits := findPatternHits(path, ted.enumerationPatterns)
		ev := ted.evidenceFrom(traversalHits, enumHits)
		ted.last.Put(ip, ev)

		if len(traversalHits) > 0 {
			ted.logAlert(ip, r, "PATH TRAVERSAL", "matched Path Traversal signature in URL or query parameters")
		}
		if len(enumHits) > 0 {
			ted.logAlert(ip, r, "ENUMERATION ATTACK", "matched Enumeration/Forced Browsing signature in URL")
		}

		next.ServeHTTP(w, r)
	})
}

func (ted *TraversalEnumDetector) Metrics(ip string) Evidence {
	return ted.last.Get(ip, SignalTraversal)
}

func (ted *TraversalEnumDetector) evidenceFrom(traversalHits, enumHits []string) Evidence {
	ev := Evidence{
		Signal: SignalTraversal,
		Details: map[string]any{
			"pathTraversalDetected": len(traversalHits) > 0,
			"enumerationDetected":   len(enumHits) > 0,
			"traversalMatches":      len(traversalHits),
			"enumerationMatches":    len(enumHits),
			"matchedPatterns":       append(append([]string{}, traversalHits...), enumHits...),
		},
	}

	hasTraversal := len(traversalHits) > 0
	hasEnum := len(enumHits) > 0
	if !hasTraversal && !hasEnum {
		return ev
	}

	ev.ThresholdCross = true
	switch {
	case hasTraversal && hasEnum:
		ev.AttackType = "path_traversal+enumeration"
		ev.Score = 100
	case hasTraversal:
		ev.AttackType = "path_traversal"
		ev.Score = 80
	default:
		ev.AttackType = "enumeration"
		ev.Score = 50
	}
	return ev
}

func findPatternHits(target string, patterns []string) []string {
	lower := strings.ToLower(target)
	var hits []string
	for _, pattern := range patterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			hits = append(hits, pattern)
		}
	}
	return hits
}

func (ted *TraversalEnumDetector) logAlert(ip string, r *http.Request, attackType string, details string) {
	fmt.Printf(`
		========================================
		SECURITY ALERT: %s DETECTED
		----------------------------------------
		IP Address     : %s
		Method         : %s
		Endpoint       : %s
		User-Agent     : %s
		Details        : %s
		Timestamp      : %s
		ACTION         : DETECTED (ALLOWING REQUEST)
		========================================
		`,
		attackType,
		ip,
		r.Method,
		r.URL.Path,
		r.Header.Get("User-Agent"),
		details,
		time.Now().Format(time.RFC3339),
	)
}
