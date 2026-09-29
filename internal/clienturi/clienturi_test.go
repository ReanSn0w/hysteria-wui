package clienturi

import (
	"net/url"
	"testing"
)

func TestBuildEscapesCredentialsAndOptions(t *testing.T) {
	got, err := Build("vpn.example.com", "user name/@", "p:a?ss#%", []byte(`
obfs:
  type: salamander
  salamander:
    password: "river & stone"
`))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "hysteria2" || u.Host != "vpn.example.com:443" || u.Hostname() != "vpn.example.com" || u.Port() != "443" || u.Path != "/" || u.Fragment != "user name/@" {
		t.Fatalf("unexpected URI: %s", got)
	}
	if user := u.User.Username(); user != "user name/@" {
		t.Fatalf("username=%q URI=%s", user, got)
	}
	if password, ok := u.User.Password(); !ok || password != "p:a?ss#%" {
		t.Fatalf("password=%q ok=%v URI=%s", password, ok, got)
	}
	if u.Query().Get("obfs") != "salamander" || u.Query().Get("obfs-password") != "river & stone" {
		t.Fatalf("query=%v", u.Query())
	}
}

func TestBuildRejectsUnsupportedObfs(t *testing.T) {
	if _, err := Build("vpn.example.com", "a", "b", []byte("obfs:\n  type: unknown\n")); err == nil {
		t.Fatal("expected error")
	}
}
