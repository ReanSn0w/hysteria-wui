package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type discardLog struct{}

func (discardLog) Logf(string, ...interface{}) {}

func TestTokenProvider(t *testing.T) {
	p := newTokenProvider("vpn.example.com")
	if err := p.Present("vpn.example.com", "abc_123-Z", "key.auth"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://vpn.example.com/.well-known/acme-challenge/abc_123-Z", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "key.auth" {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if err := p.Present("vpn.example.com", "../bad", "no"); err == nil {
		t.Fatal("expected traversal token to fail")
	}
	_ = p.CleanUp("vpn.example.com", "abc_123-Z", "key.auth")
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d", w.Code)
	}
}

func TestManagerLoadsTestCertificateAndPublishesPEM(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSigned(t, "vpn.example.com")
	sourceCert := filepath.Join(dir, "source.crt")
	sourceKey := filepath.Join(dir, "source.key")
	if err := os.WriteFile(sourceCert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceKey, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{
		DataDir: dir, Domain: "vpn.example.com", Email: "a@example.com",
		CertFile: filepath.Join(dir, "certs/fullchain.pem"), KeyFile: filepath.Join(dir, "certs/private.key"),
		TestCertFile: sourceCert, TestKeyFile: sourceKey,
	}, discardLog{})
	if err := m.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{m.cfg.CertFile, m.cfg.KeyFile} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
}

func TestCertificateReplacementReloadsHysteria(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSigned(t, "vpn.example.com")
	sourceCert := filepath.Join(dir, "source.crt")
	sourceKey := filepath.Join(dir, "source.key")
	if err := os.WriteFile(sourceCert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceKey, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	m := NewManager(Config{
		DataDir: dir, Domain: "vpn.example.com", Email: "a@example.com",
		CertFile: filepath.Join(dir, "certs/fullchain.pem"), KeyFile: filepath.Join(dir, "certs/private.key"),
		TestCertFile: sourceCert, TestKeyFile: sourceKey, Reload: func() error { reloads++; return nil },
	}, discardLog{})
	if err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
	if reloads != 0 {
		t.Fatalf("initial certificate unexpectedly reloaded Hysteria: %d", reloads)
	}
	if err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
	if reloads != 1 {
		t.Fatalf("replacement reloads=%d", reloads)
	}
}

func selfSigned(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemCertificate(der), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
