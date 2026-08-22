package signals

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
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

// sqliTunables is what the console can move at runtime, swapped whole.
type sqliTunables struct {
	enabled     bool
	sqlPatterns []string
}

// SQLiDetector inspects request path, query, and body for SQLi signatures.
type SQLiDetector struct {
	tun  atomic.Pointer[sqliTunables]
	last *lastEvidenceStore
}

func (d *SQLiDetector) settings() sqliTunables { return *d.tun.Load() }

// Apply swaps in new settings. The recent-evidence store is left alone so a
// request already seen still reports what it matched.
func (d *SQLiDetector) Apply(cfg config.AttackDetectionConfig) {
	patterns := cfg.SQLPatterns
	if len(patterns) == 0 {
		patterns = DefaultSQLiDetectorConfig().SQLPatterns
	}
	d.tun.Store(&sqliTunables{enabled: cfg.Enabled, sqlPatterns: patterns})
}

func NewSQLiDetector(cfg SQLiDetectorConfig) *SQLiDetector {
	sd := &SQLiDetector{last: newLastEvidenceStore(lastEvidenceTTL)}
	sd.Apply(config.AttackDetectionConfig{
		Enabled:     cfg.Enabled,
		SQLPatterns: cfg.SQLPatterns,
	})
	return sd
}

func (sd *SQLiDetector) Name() string { return SignalSQLi }

func (sd *SQLiDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := sd.settings()
		if !tun.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		bodyBytes, _ := readAndRestoreBody(r)
		haystack := r.URL.Path + " " + r.URL.RawQuery + " " + string(bodyBytes)
		matched := sd.findMatches(haystack, tun.sqlPatterns)
		ev := sd.evidenceFrom(matched)
		sd.last.Put(ip, r.Header.Get(RequestIDHeader), ev)

		if ev.ThresholdCross {
			sd.logAlert(ip, r, strings.Join(matched, ", "))
		}

		next.ServeHTTP(w, r)
	})
}

// Metrics returns the latest SQLi evidence for an IP, from whichever request
// produced it.
func (sd *SQLiDetector) Metrics(ip string) Evidence {
	return sd.last.Get(ip, SignalSQLi)
}

// MetricsFor returns the SQLi evidence for one request, and nothing when that
// request never reached this detector.
func (sd *SQLiDetector) MetricsFor(ip, requestID string) Evidence {
	return sd.last.GetFor(ip, requestID, SignalSQLi)
}

func (sd *SQLiDetector) findMatches(text string, patterns []string) []string {
	upper := strings.ToUpper(text)
	var matched []string
	for _, pattern := range patterns {
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
