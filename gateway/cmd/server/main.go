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

	cfg, err := config.Load(cfgPath)
	if err != nil {
		// Keep local dev friction low by falling back to the example config.
		fallbackPath := "configs/config.yaml.example"
		cfg, err = config.Load(fallbackPath)
		if err != nil {
			log.Fatalf("failed to load config from %s and fallback %s: %v", cfgPath, fallbackPath, err)
		}
		cfgPath = fallbackPath
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
	})

	log.Printf("Gateway starting on %s (backend: %s, config: %s)", listenAddr, cfg.Proxy.BackendURL, cfgPath)

	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
