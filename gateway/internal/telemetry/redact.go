package telemetry

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const maxSnippetBytes = 512

var secretKeys = []string{
	"password", "passwd", "secret", "token", "authorization",
	"api_key", "apikey", "access_token", "refresh_token", "cookie",
}

// RedactSnippet returns a short, redacted preview of a request body for agents/dashboards.
func RedactSnippet(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	trimmed := strings.TrimSpace(string(body))
	if json.Valid([]byte(trimmed)) {
		var payload any
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			redactValue(payload)
			if encoded, err := json.Marshal(payload); err == nil {
				return truncate(string(encoded), maxSnippetBytes)
			}
		}
	}
	return truncate(trimmed, maxSnippetBytes)
}

func redactValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if isSecretKey(k) {
				t[k] = "[redacted]"
				continue
			}
			redactValue(child)
		}
	case []any:
		for _, child := range t {
			redactValue(child)
		}
	}
}

func isSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for _, secret := range secretKeys {
		if strings.Contains(lower, secret) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if utf8.ValidString(s[:max]) {
		return s[:max] + "…"
	}
	return string([]rune(s)[:max/2]) + "…"
}
