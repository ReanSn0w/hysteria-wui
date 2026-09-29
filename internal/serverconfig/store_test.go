package serverconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreEnsureUsersAndComments(t *testing.T) {
	store := testStore(t)
	if got := filepath.Base(store.Path()); got != "hysteria.yaml" {
		t.Fatalf("config filename = %q, want hysteria.yaml", got)
	}
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	info, err := os.Stat(store.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("generated config permissions: %v, %v", info, err)
	}
	if err := store.AddUser("alice", "p@ss word", func() error { return nil }); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	users, err := store.Users()
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 1 || users[0].Name != "alice" || users[0].Password != "p@ss word" {
		t.Fatalf("unexpected users: %#v", users)
	}
	raw, err := store.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !strings.Contains(string(raw), "alice: p@ss word") {
		t.Fatalf("user missing from config:\n%s", raw)
	}
}

func TestStoreEnsureRejectsUnmigratedConfig(t *testing.T) {
	for _, currentExists := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_only", true: "conflict"}[currentExists], func(t *testing.T) {
			dir := t.TempDir()
			legacy := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(legacy, []byte("legacy data\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(dir, "hysteria.yaml")
			if currentExists {
				if err := os.WriteFile(current, []byte("current data\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			store := NewStore(dir, Managed{})
			err := store.Ensure()
			if err == nil || !strings.Contains(err.Error(), "config.yaml") || !strings.Contains(err.Error(), "hysteria.yaml") {
				t.Fatalf("expected migration error naming both files, got %v", err)
			}
			legacyAfter, err := os.ReadFile(legacy)
			if err != nil || string(legacyAfter) != "legacy data\n" {
				t.Fatalf("legacy changed: %q, %v", legacyAfter, err)
			}
			currentAfter, err := os.ReadFile(current)
			if currentExists {
				if err != nil || string(currentAfter) != "current data\n" {
					t.Fatalf("current changed: %q, %v", currentAfter, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected new config: %q, %v", currentAfter, err)
			}
		})
	}
}

func TestStoreEnsureRejectsDanglingLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("missing.yaml", filepath.Join(dir, "config.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	store := NewStore(dir, Managed{})
	if err := store.Ensure(); err == nil || !strings.Contains(err.Error(), "migration required") {
		t.Fatalf("expected migration error for dangling legacy config, got %v", err)
	}
	if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected new config: %v", err)
	}
}

func TestStoreEnsureRejectsIncompleteRuntime(t *testing.T) {
	for _, name := range []string{"session.key", "certs/fullchain.pem", "certs/privatekey.pem", "acme/account.key", "acme/registration.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("existing state"), 0o600); err != nil {
				t.Fatal(err)
			}
			store := NewStore(dir, Managed{})
			if err := store.Ensure(); err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Fatalf("expected incomplete migration error, got %v", err)
			}
			if _, err := os.Stat(store.Path()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected config: %v", err)
			}
		})
	}
}

func TestStoreEnsureAllowsUnrelatedFilesAndEmptyStateDirectories(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"hysteria", "notes.txt", "certs/unrelated.txt", "acme/unrelated.txt"} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("unrelated"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(dir, Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure with unrelated files: %v", err)
	}
	if _, err := store.Read(); err != nil {
		t.Fatalf("read generated config: %v", err)
	}
}

func TestStorePreservesUnknownFieldsAndComments(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.Read()
	raw = append(raw, []byte("# keep me\ndisableUDP: true\n")...)
	if err := store.Save(raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.AddUser("bob", "secret", nil); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.Read()
	if !strings.Contains(string(updated), "# keep me") || !strings.Contains(string(updated), "disableUDP: true") {
		t.Fatalf("unknown content lost:\n%s", updated)
	}
}

func TestStoreRollback(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Read()
	calls := 0
	err := store.AddUser("alice", "secret", func() error {
		calls++
		if calls == 1 {
			return errors.New("new process failed")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "previous config restored") {
		t.Fatalf("unexpected error: %v", err)
	}
	after, _ := store.Read()
	if string(before) != string(after) || calls != 2 {
		t.Fatalf("rollback failed, calls=%d\nbefore=%s\nafter=%s", calls, before, after)
	}
	info, err := os.Stat(store.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored config permissions: %v, %v", info, err)
	}
}

func TestStoreRejectsDuplicateAndInvalidUsers(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := store.AddUser("alice", "secret", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.AddUser("alice", "different", nil); err == nil {
		t.Fatal("expected duplicate user error")
	}
	for _, name := range []string{"", "bad:name", "bad\nname"} {
		if err := store.AddUser(name, "secret", nil); err == nil {
			t.Fatalf("expected invalid name %q to fail", name)
		}
	}
	if err := store.AddUser("bob", "bad\npassword", nil); err == nil {
		t.Fatal("expected invalid password to fail")
	}
	if err := store.DeleteUser("missing", nil); err == nil {
		t.Fatal("expected missing user deletion to fail")
	}
}

func TestStoreRejectsManagedChanges(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.Read()
	bad := strings.Replace(string(raw), "listen: :8443", "listen: :444", 1)
	if err := store.Validate([]byte(bad)); err == nil {
		t.Fatal("expected managed listen validation error")
	}
	bad = string(raw) + "acme: {}\n"
	if err := store.Validate([]byte(bad)); err == nil {
		t.Fatal("expected acme validation error")
	}
}

func TestStoreAccessRulesRoundTrip(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.Read()
	raw = append(raw, []byte(`sniff:
  enable: true
acl:
  inline:
    - reject(all, udp/25)
    - direct(all)
`)...)
	if err := store.Save(raw, nil); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	want := []AccessRule{
		{Action: "allow", Domain: "Rutracker.ru"},
		{Action: "block", Domain: ".ru"},
		{Action: "allow", Domain: "allowed.ru"},
		{Action: "block", Domain: "mos.ru"},
	}
	if err := store.SetAccessRules(want, func() error {
		restarts++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rules, err := store.AccessRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Rules) != 4 || rules.Rules[0] != (AccessRule{Action: "allow", Domain: "rutracker.ru"}) || rules.Rules[1] != (AccessRule{Action: "block", Domain: "ru"}) || rules.OtherCount != 2 || !rules.SniffEnabled || restarts != 1 {
		t.Fatalf("rules=%+v restarts=%d", rules, restarts)
	}
	updated, _ := store.Read()
	text := string(updated)
	allowAt := strings.Index(text, "direct(suffix:rutracker.ru)")
	blockAt := strings.Index(text, "reject(suffix:ru)")
	secondAllowAt := strings.Index(text, "direct(suffix:allowed.ru)")
	otherAt := strings.Index(text, "reject(all, udp/25)")
	if allowAt < 0 || blockAt <= allowAt || secondAllowAt <= blockAt || otherAt <= secondAllowAt || !strings.Contains(text, "direct(all)") {
		t.Fatalf("unexpected ACL order:\n%s", text)
	}
}

func TestStoreAccessRulesRejectInvalidAndFileMode(t *testing.T) {
	store := testStore(t)
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Read()
	if err := store.SetAccessRules([]AccessRule{{Action: "allow", Domain: "https://example.com/path"}}, nil); err == nil || !strings.Contains(err.Error(), "rule 1") {
		t.Fatalf("unexpected invalid-domain error: %v", err)
	}
	after, _ := store.Read()
	if string(after) != string(before) {
		t.Fatal("invalid access list changed config")
	}
	raw := append(before, []byte("acl:\n  file: /etc/hysteria/acl.txt\n")...)
	if err := store.Save(raw, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AccessRules(); err == nil || !strings.Contains(err.Error(), "acl.file") {
		t.Fatalf("unexpected file-mode read error: %v", err)
	}
	if err := store.SetAccessRules([]AccessRule{{Action: "allow", Domain: "example.ru"}}, nil); err == nil || !strings.Contains(err.Error(), "acl.file") {
		t.Fatalf("unexpected file-mode write error: %v", err)
	}
}

func TestAtomicWritePermissions(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "hysteria.yaml")
	if err := atomicWrite(filename, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return NewStore(dir, Managed{
		Listen: ":8443", CertFile: filepath.Join(dir, "certs/fullchain.pem"),
		KeyFile: filepath.Join(dir, "certs/private.key"), DecoyURL: "https://example.org",
	})
}
