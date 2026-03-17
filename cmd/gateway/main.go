package main

import (
	"log"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/proxy"
)

func main() {

	server := proxy.NewServer(proxy.Config{
		ListenAddr:   ":8080",
		BackendURL:   "http://localhost:9000",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})

	log.Println("Gateway starting on :8080")

	err := server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
