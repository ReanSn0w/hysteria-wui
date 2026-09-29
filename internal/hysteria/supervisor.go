package hysteria

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/go-pkgz/lgr"
)

type Status struct {
	Running bool
	Error   string
}

type Supervisor struct {
	opMu        sync.Mutex
	mu          sync.RWMutex
	bin         string
	config      string
	log         lgr.L
	startupWait time.Duration
	stopWait    time.Duration
	cmd         *exec.Cmd
	done        chan error
	lastErr     error
}

func NewSupervisor(bin, config string, log lgr.L, startupWait, stopWait time.Duration) *Supervisor {
	return &Supervisor{bin: bin, config: config, log: log, startupWait: startupWait, stopWait: stopWait}
}

func (s *Supervisor) Start() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.startLocked()
}

func (s *Supervisor) Restart() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.stopWait)
	defer cancel()
	if err := s.stopLocked(ctx); err != nil {
		return fmt.Errorf("stop Hysteria: %w", err)
	}
	return s.startLocked()
}

func (s *Supervisor) Stop(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.stopLocked(ctx)
}

func (s *Supervisor) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := Status{Running: s.cmd != nil}
	if s.lastErr != nil {
		status.Error = s.lastErr.Error()
	}
	return status
}

func (s *Supervisor) startLocked() error {
	s.mu.Lock()
	if s.cmd != nil {
		s.mu.Unlock()
		return errors.New("Hysteria is already running")
	}
	cmd := exec.Command(s.bin, "server", "--config", s.config) //nolint:gosec // binary and config are trusted startup settings.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("open Hysteria stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("open Hysteria stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("start Hysteria: %w", err)
	}
	done := make(chan error, 1)
	s.cmd, s.done, s.lastErr = cmd, done, nil
	s.mu.Unlock()
	go s.copyLogs("stdout", stdout)
	go s.copyLogs("stderr", stderr)
	go s.wait(cmd, done)

	timer := time.NewTimer(s.startupWait)
	defer timer.Stop()
	select {
	case err := <-done:
		if err == nil {
			err = errors.New("process exited during startup")
		}
		return fmt.Errorf("Hysteria startup: %w", err)
	case <-timer.C:
		s.log.Logf("INFO Hysteria started")
		return nil
	}
}

func (s *Supervisor) stopLocked(ctx context.Context) error {
	s.mu.RLock()
	cmd, done := s.cmd, s.done
	s.mu.RUnlock()
	if cmd == nil {
		return nil
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal Hysteria: %w", err)
	}
	select {
	case <-done:
		s.log.Logf("INFO Hysteria stopped")
		return nil
	case <-ctx.Done():
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill Hysteria after timeout: %w", err)
		}
		select {
		case <-done:
			return nil
		case <-time.After(time.Second):
			return ctx.Err()
		}
	}
}

func (s *Supervisor) wait(cmd *exec.Cmd, done chan<- error) {
	err := cmd.Wait()
	s.mu.Lock()
	if s.cmd == cmd {
		s.cmd = nil
		s.done = nil
		s.lastErr = err
	}
	s.mu.Unlock()
	done <- err
	close(done)
	if err != nil {
		s.log.Logf("ERROR Hysteria exited: %v", err)
	}
}

func (s *Supervisor) copyLogs(stream string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		s.log.Logf("INFO hysteria[%s] %s", stream, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		s.log.Logf("ERROR hysteria[%s] log read: %v", stream, err)
	}
}
