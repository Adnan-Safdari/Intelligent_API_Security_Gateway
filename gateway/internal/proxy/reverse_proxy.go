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
	proxy.Transport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		MaxIdleConns:    maxIdleConns,
		MaxConnsPerHost: maxConnsPerHost,
		IdleConnTimeout: timeout,
	}

	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {

		originalDirector(req)

		req.Header.Set("X-Gateway", "IASG")
	}

	return proxy
}
