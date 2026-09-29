package hysteria

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReanSn0w/hysteria-wui/internal/serverconfig"
)

type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) Logf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, format)
}

func TestSupervisorLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	bin, config := fakeHysteria(t)
	s := NewSupervisor(bin, config, &testLog{}, 100*time.Millisecond, time.Second)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !s.Status().Running {
		t.Fatal("expected running status")
	}
	if err := s.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s.Status().Running {
		t.Fatal("expected stopped status")
	}
}

func TestSupervisorStartupFailureDoesNotLoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	bin, config := fakeHysteria(t)
	if err := os.WriteFile(config, []byte("fail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(bin, config, &testLog{}, 300*time.Millisecond, time.Second)
	err := s.Start()
	if err == nil || !strings.Contains(err.Error(), "startup") {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if s.Status().Running {
		t.Fatal("failed process should remain stopped")
	}
}

func TestFailedRestartRollsBackConfigAndServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	bin, config := fakeHysteria(t)
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(config)
	store := serverconfig.NewStore(dir, serverconfig.Managed{
		Listen: ":8443", CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), DecoyURL: "https://example.org",
	})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(bin, store.Path(), &testLog{}, 100*time.Millisecond, time.Second)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()
	before, _ := store.Read()
	err := store.Save(append(before, []byte("fail: true\n")...), s.Restart)
	if err == nil || !strings.Contains(err.Error(), "previous config restored") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	after, _ := store.Read()
	if string(after) != string(before) || !s.Status().Running {
		t.Fatalf("rollback did not restore service: running=%v\n%s", s.Status().Running, after)
	}
}

func fakeHysteria(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "hysteria")
	config := filepath.Join(dir, "hysteria.yaml")
	script := `#!/bin/sh
config="$3"
if grep -q fail "$config"; then
  echo "bad config" >&2
  exit 7
fi
trap 'exit 0' TERM INT
echo "server up and running"
while :; do sleep 1; done
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bin, config
}
