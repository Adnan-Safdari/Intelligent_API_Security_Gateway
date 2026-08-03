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

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config from %s: %v", cfgPath, err)
	}

	if backendURLOverride != "" {
		cfg.Proxy.BackendURL = backendURLOverride
		log.Printf("Overriding backend URL from IASG_BACKEND_URL: %s", backendURLOverride)
	}

	listenAddr := net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port))

	server := proxy.NewServer(proxy.Config{
		ListenAddr:      listenAddr,
		BackendURL:      cfg.Proxy.BackendURL,
		ReadTimeout:     cfg.Server.ReadTimeout,
		WriteTimeout:    cfg.Server.WriteTimeout,
		IdleTimeout:     cfg.Server.IdleTimeout,
		ProxyTimeout:    cfg.Proxy.Timeout,
		MaxIdleConns:    cfg.Proxy.MaxIdleConns,
		MaxConnsPerHost: cfg.Proxy.MaxConnsPerHost,
		RateLimit:       cfg.Enforcement.RateLimit,
		AttackDetection: cfg.Enforcement.AttackDetection,
		BruteForce:      cfg.Enforcement.BruteForce,
	})

	log.Printf("Gateway starting on %s (backend: %s, config: %s)", listenAddr, cfg.Proxy.BackendURL, cfgPath)

	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
