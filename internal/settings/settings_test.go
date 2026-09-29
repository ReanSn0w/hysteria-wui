package settings

import (
	"os"
	"testing"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("HWUI_DOMAIN", "vpn.example.com")
	t.Setenv("HWUI_ACME_EMAIL", "admin@example.com")
	t.Setenv("HWUI_ADMIN_USER", "admin")
	t.Setenv("HWUI_ADMIN_PASSWORD", "secret")
	t.Setenv("HWUI_PANEL_PATH", "/quiet-panel")
	t.Setenv("HWUI_DECOY_URL", "https://example.org")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PanelPath != "/quiet-panel" || cfg.DecoyURL.Host != "example.org" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.HTTPAddr != ":80" || cfg.HTTPSAddr != ":443" || cfg.HysteriaAddr != ":443" {
		t.Fatalf("unexpected default listeners: HTTP=%q HTTPS=%q Hysteria=%q", cfg.HTTPAddr, cfg.HTTPSAddr, cfg.HysteriaAddr)
	}
}

func TestFromEnvRejectsAmbiguousPanelPath(t *testing.T) {
	for _, value := range []string{"/", "relative", "/panel/", "/a/../panel", "/%2fpanel", "/.well-known/acme-challenge"} {
		t.Run(value, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("HWUI_PANEL_PATH", value)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("expected %q to fail", value)
			}
		})
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"HWUI_DOMAIN": "vpn.example.com", "HWUI_ACME_EMAIL": "admin@example.com",
		"HWUI_ADMIN_USER": "admin", "HWUI_ADMIN_PASSWORD": "secret",
		"HWUI_PANEL_PATH": "/panel", "HWUI_DECOY_URL": "https://example.org",
	} {
		t.Setenv(name, value)
	}
	_ = os.Unsetenv("HWUI_TEST_CERT_FILE")
	_ = os.Unsetenv("HWUI_TEST_KEY_FILE")
}
