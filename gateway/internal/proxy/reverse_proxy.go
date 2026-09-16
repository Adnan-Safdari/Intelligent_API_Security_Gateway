package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func NewReverseProxy(cfg Config) http.Handler {
	timeout := cfg.ProxyTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = 100
	}

	maxConnsPerHost := cfg.MaxConnsPerHost
	if maxConnsPerHost <= 0 {
		maxConnsPerHost = 10
	}

	targetURL, err := url.Parse(cfg.BackendURL)
	if err != nil {
		panic("invalid backend URL: " + cfg.BackendURL)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Wrapped so the recorded backend duration is the backend call itself
	// rather than the whole middleware chain around it.
	proxy.Transport = &timedTransport{
		base: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			MaxIdleConns:    maxIdleConns,
			MaxConnsPerHost: maxConnsPerHost,
			IdleConnTimeout: timeout,
		},
	}

	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		// Read before the director runs: it rewrites the URL, not req.Host, so
		// this is still the name the client asked for.
		clientHost := req.Host

		originalDirector(req)

		// NewSingleHostReverseProxy leaves Host as the client sent it, which is
		// the gateway's own address. A backend that serves more than one site
		// from an address picks the site by that header, so it would answer for
		// a site that is not there.
		if !cfg.PreserveHost {
			req.Host = targetURL.Host
		}
		// Overwritten, never kept: a client-supplied value would let anyone
		// choose the hostname a backend puts in password-reset links.
		req.Header.Set("X-Forwarded-Host", clientHost)

		req.Header.Set("X-Gateway", "IASG")
	}

	return proxy
}
