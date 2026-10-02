package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ReanSn0w/hysteria-wui/internal/relay"
)

func main() {
	logger := log.New(os.Stderr, "hysteria-relay: ", log.LstdFlags|log.Lmsgprefix)
	cfg, err := relay.ConfigFromEnv()
	if err != nil {
		logger.Printf("configuration: %v", err)
		os.Exit(2)
	}
	cfg.Logger = logger
	server, err := relay.Listen(cfg)
	if err != nil {
		logger.Printf("startup: %v", err)
		os.Exit(1)
	}
	logger.Printf("listening on %s/udp, forwarding to %s, idle timeout %s", server.Addr(), cfg.UpstreamAddress, cfg.IdleTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("stopped: %v", err)
		os.Exit(1)
	}
}
