package signals

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// SQLiDetectorConfig controls SQL injection payload detection behavior.
type SQLiDetectorConfig struct {
	Enabled     bool
	SQLPatterns []string
}

func DefaultSQLiDetectorConfig() SQLiDetectorConfig {
	return SQLiDetectorConfig{
		Enabled: true,
		SQLPatterns: []string{
			"' OR",
			"--",
			"UNION",
			" OR 1=1",
		},
	}
}

func SQLiDetectorConfigFrom(cfg config.AttackDetectionConfig) SQLiDetectorConfig {
	return SQLiDetectorConfig{
		Enabled:     cfg.Enabled,
		SQLPatterns: cfg.SQLPatterns,
	}
}

// SQLiDetector inspects request path, query, and body for SQLi signatures.
type SQLiDetector struct {
	enabled     bool
	sqlPatterns []string
	last        *lastEvidenceStore
}

func NewSQLiDetector(cfg SQLiDetectorConfig) *SQLiDetector {
	if len(cfg.SQLPatterns) == 0 {
		cfg.SQLPatterns = DefaultSQLiDetectorConfig().SQLPatterns
	}

	return &SQLiDetector{
		enabled:     cfg.Enabled,
		sqlPatterns: cfg.SQLPatterns,
		last:        newLastEvidenceStore(lastEvidenceTTL),
	}
}

func (sd *SQLiDetector) Name() string { return SignalSQLi }

func (sd *SQLiDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sd.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		bodyBytes, _ := readAndRestoreBody(r)
		haystack := r.URL.Path + " " + r.URL.RawQuery + " " + string(bodyBytes)
		matched := sd.findMatches(haystack)
		ev := sd.evidenceFrom(matched)
		sd.last.Put(ip, ev)

		if ev.ThresholdCross {
			sd.logAlert(ip, r, strings.Join(matched, ", "))
		}

		next.ServeHTTP(w, r)
	})
}

// Metrics returns the latest SQLi evidence for an IP.
func (sd *SQLiDetector) Metrics(ip string) Evidence {
	return sd.last.Get(ip, SignalSQLi)
}

func (sd *SQLiDetector) findMatches(text string) []string {
	upper := strings.ToUpper(text)
	var matched []string
	for _, pattern := range sd.sqlPatterns {
		if strings.Contains(upper, strings.ToUpper(pattern)) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

func (sd *SQLiDetector) evidenceFrom(matched []string) Evidence {
	ev := Evidence{
		Signal: SignalSQLi,
		Details: map[string]any{
			"matchCount":      len(matched),
			"matchedPatterns": matched,
		},
	}
	if len(matched) == 0 {
		return ev
	}
	ev.ThresholdCross = true
	ev.AttackType = SignalSQLi
	switch {
	case len(matched) >= 3:
		ev.Score = 100
	case len(matched) == 2:
		ev.Score = 85
	default:
		ev.Score = 70
	}
	return ev
}

func (sd *SQLiDetector) logAlert(ip string, r *http.Request, details string) {
	fmt.Printf(`
		========================================
		SECURITY ALERT: SQL INJECTION DETECTED
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
		ip,
		r.Method,
		r.URL.Path,
		r.Header.Get("User-Agent"),
		details,
		time.Now().Format(time.RFC3339),
	)
}
