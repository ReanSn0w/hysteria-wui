package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-pkgz/lgr"

	"github.com/ReanSn0w/hysteria-wui/internal/app"
	"github.com/ReanSn0w/hysteria-wui/internal/settings"
)

func main() {
	log := lgr.New(lgr.Msec, lgr.LevelBraces)
	cfg, err := settings.FromEnv()
	if err != nil {
		log.Logf("ERROR configuration: %v", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := app.New(cfg, log)
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Logf("ERROR application stopped: %v", err)
		os.Exit(1)
	}
}
