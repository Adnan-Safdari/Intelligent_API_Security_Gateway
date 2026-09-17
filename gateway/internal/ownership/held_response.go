package ownership

import (
	"bytes"
	"net/http"
)

// heldResponse keeps the backend's answer inside the gateway until its owner
// has been checked. Nothing reaches the client while it is held, which is the
// whole point: a check made after the first byte was sent is a check made too
// late.
//
// Two answers are not held. A non-2xx status carries nobody's object, so it
// streams straight through. A 2xx body larger than limit cannot be checked:
// when unverifiable responses are allowed it streams from that point on, and
// otherwise the rest is discarded so the guard can answer 404 instead.
type heldResponse struct {
	dst              http.ResponseWriter
	streamOnOverflow bool

	header    http.Header
	status    int
	body      bytes.Buffer
	limit     int64
	overflow  bool
	streaming bool
}

func newHeldResponse(dst http.ResponseWriter, limit int64, streamOnOverflow bool) *heldResponse {
	return &heldResponse{dst: dst, header: make(http.Header), limit: limit, streamOnOverflow: streamOnOverflow}
}

func (h *heldResponse) Header() http.Header { return h.header }

func (h *heldResponse) WriteHeader(status int) {
	if h.status != 0 {
		return
	}
	h.status = status
	if status < 200 || status > 299 {
		h.startStreaming()
	}
}

func (h *heldResponse) Write(p []byte) (int, error) {
	if h.status == 0 {
		h.WriteHeader(http.StatusOK)
	}
	if h.streaming {
		return h.dst.Write(p)
	}
	if h.overflow {
		return len(p), nil
	}
	if int64(h.body.Len()+len(p)) > h.limit {
		h.overflow = true
		if h.streamOnOverflow {
			h.startStreaming()
			return h.dst.Write(p)
		}
		h.body.Reset()
		return len(p), nil
	}
	return h.body.Write(p)
}

// Flush only reaches the client once the response is no longer held.
func (h *heldResponse) Flush() {
	if !h.streaming {
		return
	}
	if flusher, ok := h.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (h *heldResponse) startStreaming() {
	h.streaming = true
	h.copyHeaderTo(h.dst)
	h.dst.WriteHeader(h.statusCode())
	if h.body.Len() > 0 {
		_, _ = h.dst.Write(h.body.Bytes())
		h.body.Reset()
	}
}

func (h *heldResponse) statusCode() int {
	if h.status == 0 {
		return http.StatusOK
	}
	return h.status
}

func (h *heldResponse) copyHeaderTo(w http.ResponseWriter) {
	dst := w.Header()
	for key, values := range h.header {
		dst[key] = append([]string(nil), values...)
	}
}

// release sends a held response unchanged.
func (h *heldResponse) release() {
	if h.streaming {
		return
	}
	h.copyHeaderTo(h.dst)
	h.dst.WriteHeader(h.statusCode())
	_, _ = h.dst.Write(h.body.Bytes())
}
