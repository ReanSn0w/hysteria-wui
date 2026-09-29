package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	cookieName     = "hwui_session"
	sessionTTL     = 12 * time.Hour
	loginWindow    = 5 * time.Minute
	maxLoginTrials = 5
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrRateLimited        = errors.New("too many login attempts")
	ErrInvalidSession     = errors.New("invalid session")
	ErrInvalidCSRF        = errors.New("invalid CSRF token")
)

type Manager struct {
	user        string
	password    string
	panelPath   string
	key         []byte
	fingerprint string
	now         func() time.Time
	mu          sync.Mutex
	attempts    map[string][]time.Time
}

type Session struct {
	Expires     int64  `json:"exp"`
	Fingerprint string `json:"fp"`
	CSRF        string `json:"csrf"`
}

func New(dataDir, panelPath, user, password string) (*Manager, error) {
	key, err := loadOrCreateKey(filepath.Join(dataDir, "session.key"))
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256([]byte(user + "\x00" + password))
	return &Manager{
		user: user, password: password, panelPath: panelPath, key: key,
		fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
		now:         time.Now, attempts: make(map[string][]time.Time),
	}, nil
}

func (m *Manager) Login(w http.ResponseWriter, remoteAddr, user, password string) (*Session, error) {
	ip := remoteIP(remoteAddr)
	if !m.allowAttempt(ip) {
		return nil, ErrRateLimited
	}
	expectedUser := sha256.Sum256([]byte(m.user))
	providedUser := sha256.Sum256([]byte(user))
	expectedPass := sha256.Sum256([]byte(m.password))
	providedPass := sha256.Sum256([]byte(password))
	valid := subtle.ConstantTimeCompare(expectedUser[:], providedUser[:]) & subtle.ConstantTimeCompare(expectedPass[:], providedPass[:])
	if valid != 1 {
		return nil, ErrInvalidCredentials
	}
	m.clearAttempts(ip)
	csrf, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate CSRF token: %w", err)
	}
	session := Session{Expires: m.now().Add(sessionTTL).Unix(), Fingerprint: m.fingerprint, CSRF: csrf}
	value, err := m.sign(session)
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: m.panelPath, MaxAge: int(sessionTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return &session, nil
}

func (m *Manager) Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: m.panelPath, MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) Session(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, ErrInvalidSession
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidSession
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidSession
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), providedMAC) {
		return nil, ErrInvalidSession
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, ErrInvalidSession
	}
	if session.Expires <= m.now().Unix() || session.Fingerprint != m.fingerprint || session.CSRF == "" {
		return nil, ErrInvalidSession
	}
	return &session, nil
}

func (m *Manager) RequireSession(loginPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.Session(r); err != nil {
			http.Redirect(w, r, loginPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) CheckCSRF(r *http.Request) error {
	session, err := m.Session(r)
	if err != nil {
		return err
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		if err := r.ParseForm(); err != nil {
			return ErrInvalidCSRF
		}
		token = r.Form.Get("csrf_token")
	}
	expected := sha256.Sum256([]byte(session.CSRF))
	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
		return ErrInvalidCSRF
	}
	return nil
}

func (m *Manager) sign(session Session) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("encode session: %w", err)
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m *Manager) allowAttempt(ip string) bool {
	now := m.now()
	cutoff := now.Add(-loginWindow)
	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.attempts[ip]
	kept := items[:0]
	for _, item := range items {
		if item.After(cutoff) {
			kept = append(kept, item)
		}
	}
	if len(kept) >= maxLoginTrials {
		m.attempts[ip] = kept
		return false
	}
	m.attempts[ip] = append(kept, now)
	return true
}

func (m *Manager) clearAttempts(ip string) {
	m.mu.Lock()
	delete(m.attempts, ip)
	m.mu.Unlock()
}

func remoteIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func loadOrCreateKey(filename string) ([]byte, error) {
	if raw, err := os.ReadFile(filename); err == nil {
		if len(raw) != 32 {
			return nil, errors.New("session key must contain exactly 32 bytes")
		}
		return raw, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read session key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return nil, fmt.Errorf("create session key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(filename), ".session-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary session key: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(name, filename); err != nil {
		return nil, err
	}
	return key, nil
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
