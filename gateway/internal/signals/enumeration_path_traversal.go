package signals

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// TraversalEnumDetectorConfig controls detection behavior for Path Traversal and Enumeration attacks.
type TraversalEnumDetectorConfig struct {
	Enabled             bool
	TraversalPatterns   []string
	EnumerationPatterns []string
}

// DefaultTraversalEnumConfig returns default signatures for Path Traversal and Enumeration.
func DefaultTraversalEnumConfig() TraversalEnumDetectorConfig {
	return TraversalEnumDetectorConfig{
		Enabled: true,
		// Common path traversal patterns (e.g., trying to access parent directories)
		TraversalPatterns: []string{
			"../",
			"..\\",
			"%2e%2e%2f", // URL encoded ../
			"%2e%2e/",
			"..%2f",
			"%2e%2e%5c", // URL encoded ..\
		},
		// Common sensitive files and directories targeted during enumeration/forced browsing
		EnumerationPatterns: []string{
			"/.env",
			"/.git",
			"/.aws",
			"/wp-admin",
			"/etc/passwd",
			"/.bash_history",
			"/.ssh",
		},
	}
}

// TraversalEnumDetector inspects URLs for path traversal and enumeration patterns.
type TraversalEnumDetector struct {
	enabled             bool
	traversalPatterns   []string
	enumerationPatterns []string
}

// NewTraversalEnumDetector creates a detector from the given configuration.
func NewTraversalEnumDetector(cfg TraversalEnumDetectorConfig) *TraversalEnumDetector {
	// If no patterns are provided, fall back to the default signatures
	if len(cfg.TraversalPatterns) == 0 {
		cfg.TraversalPatterns = DefaultTraversalEnumConfig().TraversalPatterns
	}
	if len(cfg.EnumerationPatterns) == 0 {
		cfg.EnumerationPatterns = DefaultTraversalEnumConfig().EnumerationPatterns
	}

	return &TraversalEnumDetector{
		enabled:             cfg.Enabled,
		traversalPatterns:   cfg.TraversalPatterns,
		enumerationPatterns: cfg.EnumerationPatterns,
	}
}

// Middleware detects Path Traversal and Enumeration patterns in the request URL and logs alerts.
func (ted *TraversalEnumDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If detector is disabled, skip inspection and pass to next handler
		if !ted.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		
		// 1. Check for Path Traversal in the Path and Query Parameters
		if ted.isPathTraversal(r.URL.Path) || ted.isPathTraversal(r.URL.RawQuery) {
			ted.logAlert(ip, r, "PATH TRAVERSAL", "matched Path Traversal signature in URL or query parameters")
		}

		// 2. Check for Enumeration (Forced Browsing) in the Path
		if ted.isEnumeration(r.URL.Path) {
			ted.logAlert(ip, r, "ENUMERATION ATTACK", "matched Enumeration/Forced Browsing signature in URL")
		}

		// Continue serving the request (we are just logging the incident, similar to the SQLi detector)
		next.ServeHTTP(w, r)
	})
}

// isPathTraversal checks if the target string contains any known path traversal patterns.
func (ted *TraversalEnumDetector) isPathTraversal(target string) bool {
	target = strings.ToLower(target)
	for _, pattern := range ted.traversalPatterns {
		if strings.Contains(target, pattern) {
			return true
		}
	}
	return false
}

// isEnumeration checks if the target string contains any known enumeration patterns.
func (ted *TraversalEnumDetector) isEnumeration(target string) bool {
	target = strings.ToLower(target)
	for _, pattern := range ted.enumerationPatterns {
		if strings.Contains(target, pattern) {
			return true
		}
	}
	return false
}

// logAlert prints a high-visibility security alert to the console.
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
