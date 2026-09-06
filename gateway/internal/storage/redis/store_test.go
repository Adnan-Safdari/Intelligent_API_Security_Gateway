package redisstore

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

func TestUnavailableRedisDoesNotDisableTelemetryAtStartup(t *testing.T) {
	store, err := New(config.RedisConfig{
		Enabled: true, Host: "127.0.0.1", Port: 1,
		TelemetryWriteTimeout: 20 * time.Millisecond,
	})
	if err != nil || store == nil {
		t.Fatalf("startup outage disabled the reconnectable writer: store=%v err=%v", store, err)
	}
	defer store.Close()
	for i := 0; i < 2; i++ {
		if err := store.WriteEvent(context.Background(), telemetry.Event{}); err == nil {
			t.Fatal("unavailable Redis unexpectedly accepted an event")
		}
	}
}

func TestUnresponsiveRedisBoundsEveryTelemetryWrite(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	store, err := New(config.RedisConfig{
		Enabled: true, Host: addr.IP.String(), Port: addr.Port,
		TelemetryWriteTimeout: 20 * time.Millisecond,
	})
	if err != nil || store == nil {
		t.Fatalf("unresponsive Redis prevented construction: store=%v err=%v", store, err)
	}
	defer store.Close()
	for i := 0; i < 2; i++ {
		started := time.Now()
		if err := store.WriteEvent(context.Background(), telemetry.Event{}); err == nil {
			t.Fatal("unresponsive Redis unexpectedly accepted an event")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("write exceeded its bounded Redis budget: %v", elapsed)
		}
	}
	_ = store.Close()
	_ = listener.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("timed-out telemetry writes retained their connections")
	}
}
