package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/go-pkgz/lgr"
	"gopkg.in/yaml.v3"

	"github.com/ReanSn0w/hysteria-wui/internal/auth"
	"github.com/ReanSn0w/hysteria-wui/internal/certificate"
	"github.com/ReanSn0w/hysteria-wui/internal/hysteria"
	"github.com/ReanSn0w/hysteria-wui/internal/panel"
	"github.com/ReanSn0w/hysteria-wui/internal/serverconfig"
	"github.com/ReanSn0w/hysteria-wui/internal/settings"
	webhandler "github.com/ReanSn0w/hysteria-wui/internal/web"
)

// App coordinates the process lifetime. Protocol services are attached in
// later construction stages without changing signal handling semantics.
type App struct {
	cfg        settings.Config
	log        lgr.L
	ready      atomic.Bool
	idle       atomic.Bool
	supervisor *hysteria.Supervisor
}

func New(cfg settings.Config, log lgr.L) *App {
	return &App{cfg: cfg, log: log}
}

func (a *App) Run(ctx context.Context) error {
	certFile := filepath.Join(a.cfg.DataDir, "certs", "fullchain.pem")
	keyFile := filepath.Join(a.cfg.DataDir, "certs", "privatekey.pem")
	store := serverconfig.NewStore(a.cfg.DataDir, serverconfig.Managed{
		Listen: a.cfg.HysteriaAddr, CertFile: certFile, KeyFile: keyFile, DecoyURL: a.cfg.DecoyURL.String(),
	})
	if err := store.Ensure(); err != nil {
		return fmt.Errorf("prepare Hysteria config: %w", err)
	}
	a.supervisor = hysteria.NewSupervisor(a.cfg.HysteriaBin, store.Path(), a.log, 2*time.Second, a.cfg.ShutdownWait)
	applyConfig := func() error {
		raw, err := os.ReadFile(store.Path())
		if err != nil {
			return fmt.Errorf("read Hysteria config before restart: %w", err)
		}
		var current struct {
			Auth struct {
				Users map[string]string `yaml:"userpass"`
			} `yaml:"auth"`
		}
		if err := yaml.Unmarshal(raw, &current); err != nil {
			return fmt.Errorf("inspect Hysteria users before restart: %w", err)
		}
		if len(current.Auth.Users) == 0 {
			a.idle.Store(true)
			stopCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownWait)
			defer cancel()
			return a.supervisor.Stop(stopCtx)
		}
		a.idle.Store(false)
		return a.supervisor.Restart()
	}
	authManager, err := auth.New(a.cfg.DataDir, a.cfg.PanelPath, a.cfg.AdminUser, a.cfg.AdminPass)
	if err != nil {
		return fmt.Errorf("initialize authentication: %w", err)
	}
	panelHandler, err := panel.New(panel.Config{
		BasePath: a.cfg.PanelPath, Auth: authManager, Store: store, Domain: a.cfg.Domain,
		Status: func() bool { return a.supervisor.Status().Running }, Restart: applyConfig,
	})
	if err != nil {
		return fmt.Errorf("initialize panel: %w", err)
	}
	publicHandler := webhandler.NewPublicHandler(a.cfg.PanelPath, panelHandler, a.cfg.DecoyURL, a.log)
	certManager := certificate.NewManager(certificate.Config{
		DataDir: a.cfg.DataDir, Domain: a.cfg.Domain, Email: a.cfg.ACMEEmail,
		DirectoryURL: a.cfg.ACMEDirectory, CertFile: certFile, KeyFile: keyFile,
		TestCertFile: a.cfg.TestCertFile, TestKeyFile: a.cfg.TestKeyFile,
		Reload: a.supervisor.Restart,
	}, a.log)

	health := &http.Server{
		Addr:              a.cfg.HealthAddr,
		Handler:           a.healthHandler(),
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	httpServer := &http.Server{
		Addr: a.cfg.HTTPAddr, Handler: certManager.HTTPHandler(webhandler.HTTPRedirect(a.cfg.Domain)),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	httpsServer := &http.Server{
		Addr: a.cfg.HTTPSAddr, Handler: publicHandler, TLSConfig: certManager.TLSConfig(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}

	healthLn, err := net.Listen("tcp", a.cfg.HealthAddr)
	if err != nil {
		return fmt.Errorf("listen for health checks: %w", err)
	}
	httpLn, err := net.Listen("tcp", a.cfg.HTTPAddr)
	if err != nil {
		_ = healthLn.Close()
		return fmt.Errorf("listen for HTTP: %w", err)
	}
	errCh := make(chan error, 3)
	serve := func(name string, server *http.Server, listener net.Listener, tls bool) {
		go func() {
			a.log.Logf("INFO %s listener started on %s", name, listener.Addr())
			var serveErr error
			if tls {
				serveErr = server.ServeTLS(listener, "", "")
			} else {
				serveErr = server.Serve(listener)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", name, serveErr)
			}
		}()
	}
	serve("health", health, healthLn, false)
	serve("HTTP", httpServer, httpLn, false)

	shutdown := func() error {
		a.ready.Store(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownWait)
		defer cancel()
		return errors.Join(
			httpsServer.Shutdown(shutdownCtx), httpServer.Shutdown(shutdownCtx), health.Shutdown(shutdownCtx),
			a.supervisor.Stop(shutdownCtx),
		)
	}
	if err := certManager.Ensure(); err != nil {
		_ = shutdown()
		return fmt.Errorf("prepare TLS certificate: %w", err)
	}
	users, err := store.Users()
	if err != nil {
		_ = shutdown()
		return fmt.Errorf("read initial users: %w", err)
	}
	if len(users) == 0 {
		a.idle.Store(true)
		a.log.Logf("WARN Hysteria is not started until the first user is created")
	} else if err := a.supervisor.Start(); err != nil {
		_ = shutdown()
		return err
	}
	httpsLn, err := net.Listen("tcp", a.cfg.HTTPSAddr)
	if err != nil {
		_ = shutdown()
		return fmt.Errorf("listen for HTTPS: %w", err)
	}
	serve("HTTPS", httpsServer, httpsLn, true)
	go certManager.Run(ctx)
	a.ready.Store(true)

	var runErr error
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case runErr = <-errCh:
	}
	if err := shutdown(); err != nil {
		return errors.Join(runErr, fmt.Errorf("shutdown: %w", err))
	}
	return runErr
}

func (a *App) healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !a.ready.Load() || a.supervisor == nil || (!a.idle.Load() && !a.supervisor.Status().Running) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}
