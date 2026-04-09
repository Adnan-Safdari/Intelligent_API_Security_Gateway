package proxy

import (
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// SecurityMiddleware is kept as a compatibility adapter.
// Attack detection logic now lives in internal/signals.

func SecurityMiddleware(next http.Handler) http.Handler {
	detector := signals.NewSQLiDetector(signals.DefaultSQLiDetectorConfig())
	return detector.Middleware(next)
}
