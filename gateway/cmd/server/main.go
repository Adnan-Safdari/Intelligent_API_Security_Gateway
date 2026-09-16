package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/proxy"
)

func main() {
	cfgPath := os.Getenv("IASG_CONFIG")
	if cfgPath == "" {
		cfgPath = "configs/config.yaml"
	}

	backendURLOverride := os.Getenv("IASG_BACKEND_URL")
	redisHostOverride := os.Getenv("IASG_REDIS_HOST")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config from %s: %v", cfgPath, err)
	}

	if backendURLOverride != "" {
		cfg.Proxy.BackendURL = backendURLOverride
		log.Printf("Overriding backend URL from IASG_BACKEND_URL: %s", backendURLOverride)
	}
	if redisHostOverride != "" {
		cfg.Storage.Redis.Host = redisHostOverride
		log.Printf("Overriding Redis host from IASG_REDIS_HOST: %s", redisHostOverride)
	}

	listenAddr := net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port))

	server := proxy.NewServer(proxy.Config{
		ListenAddr:        listenAddr,
		BackendURL:        cfg.Proxy.BackendURL,
		PreserveHost:      cfg.Proxy.PreserveHost,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ProxyTimeout:      cfg.Proxy.Timeout,
		MaxIdleConns:      cfg.Proxy.MaxIdleConns,
		MaxConnsPerHost:   cfg.Proxy.MaxConnsPerHost,
		MaxBodyBytes:      cfg.Server.MaxBodyBytes,
		Routes:            cfg.Routes,
		RateLimit:         cfg.Enforcement.RateLimit,
		AdaptiveRateLimit: cfg.Enforcement.AdaptiveRateLimit,
		AttackDetection:   cfg.Enforcement.AttackDetection,
		BruteForce:        cfg.Enforcement.BruteForce,
		UnknownRouteScan:  cfg.Enforcement.UnknownRouteScan,
		ObjectEnumeration: cfg.Enforcement.ObjectEnumeration,
		Enumeration:       cfg.Enforcement.Enumeration,
		IPReputation:      cfg.Enforcement.IPReputation,
		Policy:            cfg.Enforcement.Policy,
		Block:             cfg.Enforcement.Block,
		Throttle:          cfg.Enforcement.Throttle,
		Redis:             cfg.Storage.Redis,
		TrustedProxies:    cfg.Server.TrustedProxies,
	})

	log.Printf("Gateway starting on %s (backend: %s, config: %s)", listenAddr, cfg.Proxy.BackendURL, cfgPath)

	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
