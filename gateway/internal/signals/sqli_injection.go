package signals

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// SQLiDetectorConfig controls SQL injection payload detection behavior.
type SQLiDetectorConfig struct {
	Enabled     bool
	SQLPatterns []string
}

// DefaultSQLiDetectorConfig returns default SQLi signatures.
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

// SQLiDetector inspects request bodies and logs SQLi alerts.
type SQLiDetector struct {
	enabled     bool
	sqlPatterns []string
}

// NewSQLiDetector creates a SQLi detector from configuration.
func NewSQLiDetector(cfg SQLiDetectorConfig) *SQLiDetector {
	if len(cfg.SQLPatterns) == 0 {
		cfg.SQLPatterns = DefaultSQLiDetectorConfig().SQLPatterns
	}

	return &SQLiDetector{
		enabled:     cfg.Enabled,
		sqlPatterns: cfg.SQLPatterns,
	}
}

// Middleware detects SQLi patterns and logs alerts; it does not block requests.
func (sd *SQLiDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sd.enabled {
			next.ServeHTTP(w, r)
			return
		}

		bodyBytes, _ := readAndRestoreBody(r)
		if sd.isSQLi(string(bodyBytes)) {
			ip := netutil.ClientIP(r.RemoteAddr)
			sd.logAlert(ip, r, "matched SQLi signature in request body")
		}

		next.ServeHTTP(w, r)
	})
}

func (sd *SQLiDetector) isSQLi(body string) bool {
	body = strings.ToUpper(body)
	for _, pattern := range sd.sqlPatterns {
		if strings.Contains(body, strings.ToUpper(pattern)) {
			return true
		}
	}
	return false
}

func (sd *SQLiDetector) logAlert(ip string, r *http.Request, details string) {
	fmt.Printf(
		"SECURITY ALERT [SQL_INJECTION] ip=%s method=%s path=%s user-agent=%q details=%s time=%s\n",
		ip,
		r.Method,
		r.URL.Path,
		r.Header.Get("User-Agent"),
		details,
		time.Now().Format(time.RFC3339),
	)
}

func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, err
}
