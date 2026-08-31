package signals

import (
	"bytes"
	"io"
	"net/http"
)

// Unbounded on its own. It is safe only because proxy.BodyLimitMiddleware runs
// first and has already replaced r.Body with a buffer of at most the configured
// size. Detectors must stay above the proxy and below that cap; moving this
// read anywhere the cap does not cover restores the exhaustion it prevents.
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, err
}
