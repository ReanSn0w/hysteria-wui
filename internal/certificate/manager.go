package certificate

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-pkgz/lgr"
)

const (
	defaultRenewBefore   = 30 * 24 * time.Hour
	defaultCheckInterval = 12 * time.Hour
)

type Config struct {
	DataDir       string
	Domain        string
	Email         string
	DirectoryURL  string
	CertFile      string
	KeyFile       string
	TestCertFile  string
	TestKeyFile   string
	RenewBefore   time.Duration
	CheckInterval time.Duration
	Reload        func() error
}

type Manager struct {
	cfg      Config
	log      lgr.L
	provider *tokenProvider
	cert     atomic.Pointer[tls.Certificate]
	mu       sync.Mutex
	issueFn  func() error
}

func NewManager(cfg Config, log lgr.L) *Manager {
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = defaultRenewBefore
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = defaultCheckInterval
	}
	m := &Manager{cfg: cfg, log: log, provider: newTokenProvider(cfg.Domain)}
	m.issueFn = m.issue
	return m
}

func (m *Manager) Ensure() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(m.cfg.CertFile), 0o700); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if m.cfg.TestCertFile != "" {
		certPEM, err := os.ReadFile(m.cfg.TestCertFile)
		if err != nil {
			return fmt.Errorf("read test certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(m.cfg.TestKeyFile)
		if err != nil {
			return fmt.Errorf("read test key: %w", err)
		}
		return m.publish(certPEM, keyPEM)
	}
	if cert, leaf, err := loadCertificate(m.cfg.CertFile, m.cfg.KeyFile, m.cfg.Domain); err == nil {
		m.cert.Store(cert)
		if time.Until(leaf.NotAfter) > m.cfg.RenewBefore {
			m.log.Logf("INFO certificate loaded, expires %s", leaf.NotAfter.UTC().Format(time.RFC3339))
			return nil
		}
		m.log.Logf("INFO certificate renewal required, expires %s", leaf.NotAfter.UTC().Format(time.RFC3339))
		if leaf.NotAfter.After(time.Now()) {
			if err := m.issueFn(); err != nil {
				m.log.Logf("WARN certificate renewal deferred: %v", err)
				return nil
			}
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		m.log.Logf("WARN existing certificate is unusable: %v", err)
	}
	return m.issueFn()
}

func (m *Manager) Run(ctx context.Context) {
	backoff := time.Minute
	next := m.cfg.CheckInterval + time.Duration(rand.Int64N(int64(m.cfg.CheckInterval/10+1)))
	for {
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := m.Ensure(); err != nil {
			m.log.Logf("ERROR certificate renewal: %v", err)
			next = backoff
			backoff *= 2
			if backoff > 6*time.Hour {
				backoff = 6 * time.Hour
			}
			continue
		}
		backoff = time.Minute
		next = m.cfg.CheckInterval + time.Duration(rand.Int64N(int64(m.cfg.CheckInterval/10+1)))
	}
}

func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := m.cert.Load()
	if cert == nil {
		return nil, errors.New("certificate is not ready")
	}
	return cert, nil
}

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate}
}

func (m *Manager) HTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
			m.provider.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) issue() error {
	account, err := loadOrCreateAccount(filepath.Join(m.cfg.DataDir, "acme"), m.cfg.Email)
	if err != nil {
		return err
	}
	legoCfg := lego.NewConfig(account)
	legoCfg.Certificate.KeyType = certcrypto.EC256
	if m.cfg.DirectoryURL != "" {
		legoCfg.CADirURL = m.cfg.DirectoryURL
	}
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("create ACME client: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(m.provider); err != nil {
		return fmt.Errorf("set HTTP-01 provider: %w", err)
	}
	if account.registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("register ACME account: %w", err)
		}
		account.registration = reg
		if err := account.saveRegistration(); err != nil {
			return err
		}
	}
	var privateKey crypto.PrivateKey
	if keyPEM, err := os.ReadFile(m.cfg.KeyFile); err == nil {
		privateKey, err = certcrypto.ParsePEMPrivateKey(keyPEM)
		if err != nil {
			return fmt.Errorf("parse certificate private key: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read certificate private key: %w", err)
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{m.cfg.Domain}, PrivateKey: privateKey, Bundle: true,
	})
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}
	if err := m.publish(resource.Certificate, resource.PrivateKey); err != nil {
		return err
	}
	m.log.Logf("INFO certificate issued for %s", m.cfg.Domain)
	return nil
}

func (m *Manager) publish(certPEM, keyPEM []byte) error {
	wasActive := m.cert.Load() != nil
	cert, leaf, err := parseCertificate(certPEM, keyPEM, m.cfg.Domain)
	if err != nil {
		return err
	}
	// The same certificate key is reused for renewal. Publishing the key first
	// and replacing only the certificate on renewal prevents a transient key
	// mismatch while Hysteria reads both files during a handshake.
	if err := atomicWrite(m.cfg.KeyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("publish certificate key: %w", err)
	}
	if err := atomicWrite(m.cfg.CertFile, certPEM, 0o600); err != nil {
		return fmt.Errorf("publish certificate: %w", err)
	}
	cert.Leaf = leaf
	m.cert.Store(cert)
	if wasActive && m.cfg.Reload != nil {
		if err := m.cfg.Reload(); err != nil {
			return fmt.Errorf("reload Hysteria after certificate renewal: %w", err)
		}
	}
	return nil
}

func loadCertificate(certFile, keyFile, domain string) (*tls.Certificate, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	return parseCertificate(certPEM, keyPEM, domain)
}

func parseCertificate(certPEM, keyPEM []byte, domain string) (*tls.Certificate, *x509.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, nil, fmt.Errorf("certificate does not cover %s: %w", domain, err)
	}
	return &cert, leaf, nil
}

type account struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
	dir          string
}

func (a *account) GetEmail() string                        { return a.email }
func (a *account) GetRegistration() *registration.Resource { return a.registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

func (a *account) saveRegistration() error {
	raw, err := json.MarshalIndent(a.registration, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ACME registration: %w", err)
	}
	if err := atomicWrite(filepath.Join(a.dir, "registration.json"), append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("save ACME registration: %w", err)
	}
	return nil
}

func loadOrCreateAccount(dir, email string) (*account, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME directory: %w", err)
	}
	keyFile := filepath.Join(dir, "account.key")
	var key crypto.PrivateKey
	if raw, err := os.ReadFile(keyFile); err == nil {
		key, err = certcrypto.ParsePEMPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		key, err = certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("generate ACME account key: %w", err)
		}
		if err := atomicWrite(keyFile, certcrypto.PEMEncode(key), 0o600); err != nil {
			return nil, fmt.Errorf("save ACME account key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	a := &account{email: email, key: key, dir: dir}
	if raw, err := os.ReadFile(filepath.Join(dir, "registration.json")); err == nil {
		if err := json.Unmarshal(raw, &a.registration); err != nil {
			return nil, fmt.Errorf("parse ACME registration: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read ACME registration: %w", err)
	}
	return a, nil
}

func atomicWrite(filename string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".publish-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filename); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type tokenProvider struct {
	domain string
	mu     sync.RWMutex
	tokens map[string]string
}

func newTokenProvider(domain string) *tokenProvider {
	return &tokenProvider{domain: domain, tokens: make(map[string]string)}
}

func (p *tokenProvider) Present(domain, token, keyAuth string) error {
	if domain != p.domain {
		return fmt.Errorf("unexpected challenge domain %q", domain)
	}
	if !validToken(token) {
		return errors.New("invalid HTTP-01 token")
	}
	p.mu.Lock()
	p.tokens[token] = keyAuth
	p.mu.Unlock()
	return nil
}

func (p *tokenProvider) CleanUp(_ string, token, _ string) error {
	p.mu.Lock()
	delete(p.tokens, token)
	p.mu.Unlock()
	return nil
}

func (p *tokenProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, http01.PathPrefix)
	if !validToken(token) {
		http.NotFound(w, r)
		return
	}
	host := r.Host
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		host = strings.Trim(host[:colon], "[]")
	}
	if !strings.EqualFold(host, p.domain) {
		http.NotFound(w, r)
		return
	}
	p.mu.RLock()
	keyAuth, ok := p.tokens[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(keyAuth))
}

func validToken(token string) bool {
	if len(token) == 0 || len(token) > 512 {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func pemCertificate(rawDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawDER})
}
