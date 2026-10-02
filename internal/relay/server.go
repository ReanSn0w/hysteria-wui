package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultListenAddress = ":8443"
	defaultIdleTimeout   = 5 * time.Minute
	defaultSocketBuffer  = 4 * 1024 * 1024
	maxUDPPacketSize     = 65535
)

type Config struct {
	ListenAddress   string
	UpstreamAddress string
	IdleTimeout     time.Duration
	SocketBuffer    int
	Logger          *log.Logger
}

func ConfigFromEnv() (Config, error) {
	cfg := Config{
		ListenAddress:   valueOrDefault("HYSTERIA_RELAY_LISTEN", defaultListenAddress),
		UpstreamAddress: strings.TrimSpace(os.Getenv("HYSTERIA_RELAY_UPSTREAM")),
		IdleTimeout:     defaultIdleTimeout,
		SocketBuffer:    defaultSocketBuffer,
	}
	if cfg.UpstreamAddress == "" {
		return Config{}, errors.New("HYSTERIA_RELAY_UPSTREAM is required")
	}
	if value := strings.TrimSpace(os.Getenv("HYSTERIA_RELAY_IDLE_TIMEOUT")); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return Config{}, fmt.Errorf("HYSTERIA_RELAY_IDLE_TIMEOUT must be a positive Go duration: %q", value)
		}
		cfg.IdleTimeout = timeout
	}
	if value := strings.TrimSpace(os.Getenv("HYSTERIA_RELAY_SOCKET_BUFFER")); value != "" {
		size, err := strconv.Atoi(value)
		if err != nil || size < maxUDPPacketSize {
			return Config{}, fmt.Errorf("HYSTERIA_RELAY_SOCKET_BUFFER must be an integer of at least %d bytes: %q", maxUDPPacketSize, value)
		}
		cfg.SocketBuffer = size
	}
	return cfg, nil
}

func valueOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

type Server struct {
	listener        *net.UDPConn
	upstreamAddress *net.UDPAddr
	upstreamNetwork string
	idleTimeout     time.Duration
	socketBuffer    int
	logger          *log.Logger

	mu       sync.Mutex
	sessions map[string]*session
	wg       sync.WaitGroup
}

type session struct {
	client   *net.UDPAddr
	upstream *net.UDPConn
}

func Listen(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddress) == "" {
		return nil, errors.New("listen address is required")
	}
	if strings.TrimSpace(cfg.UpstreamAddress) == "" {
		return nil, errors.New("upstream address is required")
	}
	if cfg.IdleTimeout <= 0 {
		return nil, errors.New("idle timeout must be positive")
	}
	if cfg.SocketBuffer == 0 {
		cfg.SocketBuffer = defaultSocketBuffer
	}
	if cfg.SocketBuffer < maxUDPPacketSize {
		return nil, fmt.Errorf("socket buffer must be at least %d bytes", maxUDPPacketSize)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	listenAddress, err := net.ResolveUDPAddr("udp", cfg.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address: %w", err)
	}
	upstreamAddress, err := net.ResolveUDPAddr("udp", cfg.UpstreamAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream address: %w", err)
	}
	listener, err := net.ListenUDP(udpNetwork(listenAddress), listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for UDP: %w", err)
	}
	server := &Server{
		listener: listener, upstreamAddress: upstreamAddress, upstreamNetwork: udpNetwork(upstreamAddress),
		idleTimeout: cfg.IdleTimeout, socketBuffer: cfg.SocketBuffer, logger: cfg.Logger,
		sessions: make(map[string]*session),
	}
	server.setBuffers(listener, "listener")
	return server, nil
}

func udpNetwork(address *net.UDPAddr) string {
	if address.IP == nil {
		return "udp"
	}
	if address.IP.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func (s *Server) Addr() net.Addr { return s.listener.LocalAddr() }

func (s *Server) Serve(ctx context.Context) error {
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-stopped:
		}
	}()

	buffer := make([]byte, maxUDPPacketSize)
	var serveErr error
	for {
		n, client, err := s.listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = fmt.Errorf("read client UDP: %w", err)
			}
			break
		}
		if err := s.forward(client, buffer[:n]); err != nil {
			s.logger.Printf("relay client %s: %v", client, err)
		}
	}
	close(stopped)
	s.closeSessions()
	s.wg.Wait()
	return serveErr
}

func (s *Server) forward(client *net.UDPAddr, packet []byte) error {
	key := client.String()
	current, err := s.session(key, client)
	if err != nil {
		return err
	}
	if err := current.upstream.SetReadDeadline(time.Now().Add(s.idleTimeout)); err != nil {
		s.dropSession(key, current)
		return fmt.Errorf("refresh upstream deadline: %w", err)
	}
	if _, err := current.upstream.Write(packet); err != nil {
		s.dropSession(key, current)
		return fmt.Errorf("write upstream: %w", err)
	}
	return nil
}

func (s *Server) session(key string, client *net.UDPAddr) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.sessions[key]; current != nil {
		return current, nil
	}
	upstream, err := net.DialUDP(s.upstreamNetwork, nil, s.upstreamAddress)
	if err != nil {
		return nil, fmt.Errorf("open upstream session: %w", err)
	}
	s.setBuffers(upstream, "upstream session")
	current := &session{client: cloneUDPAddr(client), upstream: upstream}
	if err := upstream.SetReadDeadline(time.Now().Add(s.idleTimeout)); err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("set upstream deadline: %w", err)
	}
	s.sessions[key] = current
	s.wg.Add(1)
	go s.forwardResponses(key, current)
	return current, nil
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func (s *Server) forwardResponses(key string, current *session) {
	defer s.wg.Done()
	defer s.dropSession(key, current)
	buffer := make([]byte, maxUDPPacketSize)
	for {
		n, err := current.upstream.Read(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					s.logger.Printf("relay upstream for %s: %v", current.client, err)
				}
			}
			return
		}
		if _, err := s.listener.WriteToUDP(buffer[:n], current.client); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.Printf("relay response to %s: %v", current.client, err)
			}
			return
		}
		if err := current.upstream.SetReadDeadline(time.Now().Add(s.idleTimeout)); err != nil {
			return
		}
	}
}

func (s *Server) dropSession(key string, current *session) {
	s.mu.Lock()
	if s.sessions[key] == current {
		delete(s.sessions, key)
	}
	s.mu.Unlock()
	_ = current.upstream.Close()
}

func (s *Server) closeSessions() {
	s.mu.Lock()
	current := make([]*session, 0, len(s.sessions))
	for key, item := range s.sessions {
		delete(s.sessions, key)
		current = append(current, item)
	}
	s.mu.Unlock()
	for _, item := range current {
		_ = item.upstream.Close()
	}
}

func (s *Server) setBuffers(connection *net.UDPConn, name string) {
	if err := connection.SetReadBuffer(s.socketBuffer); err != nil {
		s.logger.Printf("set %s read buffer: %v", name, err)
	}
	if err := connection.SetWriteBuffer(s.socketBuffer); err != nil {
		s.logger.Printf("set %s write buffer: %v", name, err)
	}
}
