package settings

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const (
	defaultDataDir      = "/var/lib/hysteria-wui"
	defaultHTTPAddr     = ":80"
	defaultHTTPSAddr    = ":443"
	defaultHealthAddr   = "127.0.0.1:9090"
	defaultHysteriaAddr = ":443"
)

// Config contains immutable process configuration loaded at startup.
type Config struct {
	Domain        string
	ACMEEmail     string
	AdminUser     string
	AdminPass     string
	PanelPath     string
	DecoyURL      *url.URL
	DataDir       string
	HTTPAddr      string
	HTTPSAddr     string
	HealthAddr    string
	HysteriaAddr  string
	HysteriaBin   string
	ACMEDirectory string
	TestCertFile  string
	TestKeyFile   string
	ShutdownWait  time.Duration
}

// FromEnv loads and validates startup configuration. HWUI_TEST_* variables are
// intentionally undocumented production escape hatches used by automated
// tests and local smoke checks.
func FromEnv() (Config, error) {
	cfg := Config{
		Domain:        strings.TrimSpace(os.Getenv("HWUI_DOMAIN")),
		ACMEEmail:     strings.TrimSpace(os.Getenv("HWUI_ACME_EMAIL")),
		AdminUser:     os.Getenv("HWUI_ADMIN_USER"),
		AdminPass:     os.Getenv("HWUI_ADMIN_PASSWORD"),
		PanelPath:     os.Getenv("HWUI_PANEL_PATH"),
		DataDir:       valueOrDefault("HWUI_DATA_DIR", defaultDataDir),
		HTTPAddr:      valueOrDefault("HWUI_HTTP_ADDR", defaultHTTPAddr),
		HTTPSAddr:     valueOrDefault("HWUI_HTTPS_ADDR", defaultHTTPSAddr),
		HealthAddr:    valueOrDefault("HWUI_HEALTH_ADDR", defaultHealthAddr),
		HysteriaAddr:  valueOrDefault("HWUI_HYSTERIA_ADDR", defaultHysteriaAddr),
		HysteriaBin:   valueOrDefault("HWUI_HYSTERIA_BIN", "/usr/local/bin/hysteria"),
		ACMEDirectory: strings.TrimSpace(os.Getenv("HWUI_ACME_DIRECTORY")),
		TestCertFile:  strings.TrimSpace(os.Getenv("HWUI_TEST_CERT_FILE")),
		TestKeyFile:   strings.TrimSpace(os.Getenv("HWUI_TEST_KEY_FILE")),
		ShutdownWait:  10 * time.Second,
	}

	var missing []string
	for name, value := range map[string]string{
		"HWUI_DOMAIN":         cfg.Domain,
		"HWUI_ACME_EMAIL":     cfg.ACMEEmail,
		"HWUI_ADMIN_USER":     cfg.AdminUser,
		"HWUI_ADMIN_PASSWORD": cfg.AdminPass,
		"HWUI_PANEL_PATH":     cfg.PanelPath,
		"HWUI_DECOY_URL":      os.Getenv("HWUI_DECOY_URL"),
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("required environment variables are empty: %s", strings.Join(missing, ", "))
	}

	if err := validateDomain(cfg.Domain); err != nil {
		return Config{}, fmt.Errorf("HWUI_DOMAIN: %w", err)
	}
	panelPath, err := normalizePanelPath(cfg.PanelPath)
	if err != nil {
		return Config{}, fmt.Errorf("HWUI_PANEL_PATH: %w", err)
	}
	cfg.PanelPath = panelPath

	decoy, err := validateDecoyURL(os.Getenv("HWUI_DECOY_URL"))
	if err != nil {
		return Config{}, fmt.Errorf("HWUI_DECOY_URL: %w", err)
	}
	cfg.DecoyURL = decoy

	for name, addr := range map[string]string{
		"HWUI_HTTP_ADDR": cfg.HTTPAddr, "HWUI_HTTPS_ADDR": cfg.HTTPSAddr,
		"HWUI_HEALTH_ADDR": cfg.HealthAddr, "HWUI_HYSTERIA_ADDR": cfg.HysteriaAddr,
	} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Config{}, fmt.Errorf("%s: invalid listen address: %w", name, err)
		}
	}
	if (cfg.TestCertFile == "") != (cfg.TestKeyFile == "") {
		return Config{}, errors.New("HWUI_TEST_CERT_FILE and HWUI_TEST_KEY_FILE must be set together")
	}
	return cfg, nil
}

func valueOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func validateDomain(value string) error {
	if strings.ContainsAny(value, "/:@?#") || strings.Contains(value, " ") {
		return errors.New("must be a DNS name without scheme, port, path, or whitespace")
	}
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return errors.New("invalid DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid DNS label")
		}
	}
	return nil
}

func normalizePanelPath(value string) (string, error) {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "", errors.New("must be an absolute URL path")
	}
	if len(value) > 1 && strings.HasSuffix(value, "/") {
		return "", errors.New("must not have a trailing slash")
	}
	if strings.ContainsAny(value, "?#%\\") {
		return "", errors.New("must not contain query, fragment, escapes, or backslashes")
	}
	clean := path.Clean(value)
	if clean == "." || clean == "/" || clean != value {
		return "", errors.New("must be a normalized non-root path")
	}
	if clean == "/.well-known" || strings.HasPrefix(clean, "/.well-known/") {
		return "", errors.New("conflicts with the ACME challenge path")
	}
	return clean, nil
}

func validateDecoyURL(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be an https origin without credentials, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("must not include a path")
	}
	u.Path = ""
	return u, nil
}
