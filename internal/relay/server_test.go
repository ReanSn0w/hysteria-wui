package relay

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

type observation struct {
	message string
	source  string
}

func TestRelayMultipleClientsAndLongSession(t *testing.T) {
	echo, observations := startEchoServer(t)
	server, err := Listen(Config{
		ListenAddress: "127.0.0.1:0", UpstreamAddress: echo.LocalAddr().String(),
		IdleTimeout: 750 * time.Millisecond, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	relayAddress := server.Addr().(*net.UDPAddr)
	clients := make([]*net.UDPConn, 3)
	for i := range clients {
		clients[i], err = net.DialUDP("udp4", nil, relayAddress)
		if err != nil {
			t.Fatal(err)
		}
		defer clients[i].Close()
	}

	var wg sync.WaitGroup
	for i, client := range clients {
		wg.Add(1)
		go func(index int, connection *net.UDPConn) {
			defer wg.Done()
			message := fmt.Sprintf("client-%d", index)
			if got := exchange(t, connection, message); got != message {
				t.Errorf("response = %q, want %q", got, message)
			}
		}(i, client)
	}
	wg.Wait()

	sources := make(map[string]string)
	for range clients {
		seen := <-observations
		sources[seen.message] = seen.source
	}
	if len(sources) != len(clients) {
		t.Fatalf("upstream sessions = %d, want %d: %#v", len(sources), len(clients), sources)
	}
	unique := make(map[string]struct{})
	for _, source := range sources {
		unique[source] = struct{}{}
	}
	if len(unique) != len(clients) {
		t.Fatalf("clients shared upstream source sockets: %#v", sources)
	}

	firstSource := sources["client-0"]
	for i := 0; i < 3; i++ {
		time.Sleep(250 * time.Millisecond)
		message := fmt.Sprintf("keepalive-%d", i)
		if got := exchange(t, clients[0], message); got != message {
			t.Fatalf("keepalive response = %q, want %q", got, message)
		}
		seen := <-observations
		if seen.message != message || seen.source != firstSource {
			t.Fatalf("long session changed: got %+v, want source %s", seen, firstSource)
		}
	}
}

func TestRelayExpiresIdleSession(t *testing.T) {
	echo, observations := startEchoServer(t)
	server, err := Listen(Config{
		ListenAddress: "127.0.0.1:0", UpstreamAddress: echo.LocalAddr().String(),
		IdleTimeout: 100 * time.Millisecond, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()

	client, err := net.DialUDP("udp4", nil, server.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got := exchange(t, client, "first"); got != "first" {
		t.Fatalf("response = %q", got)
	}
	first := <-observations

	deadline := time.Now().Add(2 * time.Second)
	for sessionCount(server) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count := sessionCount(server); count != 0 {
		t.Fatalf("idle sessions = %d, want 0", count)
	}
	if got := exchange(t, client, "second"); got != "second" {
		t.Fatalf("response = %q", got)
	}
	second := <-observations
	if second.source == first.source {
		t.Logf("OS reused upstream port %s after idle cleanup", second.source)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("HYSTERIA_RELAY_UPSTREAM", "main.example.com:443")
	t.Setenv("HYSTERIA_RELAY_LISTEN", ":9443")
	t.Setenv("HYSTERIA_RELAY_IDLE_TIMEOUT", "15m")
	t.Setenv("HYSTERIA_RELAY_SOCKET_BUFFER", "1048576")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamAddress != "main.example.com:443" || cfg.ListenAddress != ":9443" || cfg.IdleTimeout != 15*time.Minute || cfg.SocketBuffer != 1048576 {
		t.Fatalf("unexpected config: %+v", cfg)
	}

	t.Setenv("HYSTERIA_RELAY_IDLE_TIMEOUT", "never")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}

func exchange(t *testing.T, client *net.UDPConn, message string) string {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return string(buffer[:n])
}

func startEchoServer(t *testing.T) (*net.UDPConn, <-chan observation) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	observations := make(chan observation, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxUDPPacketSize)
		for {
			n, source, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			message := string(buffer[:n])
			observations <- observation{message: message, source: source.String()}
			_, _ = server.WriteToUDP(buffer[:n], source)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	return server, observations
}

func sessionCount(server *Server) int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.sessions)
}
