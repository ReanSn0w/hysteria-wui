package auth

import (
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginSessionCSRFAndLogout(t *testing.T) {
	m, err := New(t.TempDir(), "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	session, err := m.Login(w, "192.0.2.1:1234", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	result := w.Result()
	if len(result.Cookies()) != 1 {
		t.Fatal("missing session cookie")
	}
	cookie := result.Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/quiet" || cookie.SameSite != 2 {
		t.Fatalf("unsafe cookie: %#v", cookie)
	}
	r := httptest.NewRequest("POST", "https://example.com/quiet/users", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	if _, err := m.Session(r); err != nil {
		t.Fatalf("Session: %v", err)
	}
	if err := m.CheckCSRF(r); err != nil {
		t.Fatalf("CheckCSRF: %v", err)
	}
	r.Header.Set("X-CSRF-Token", "bad")
	if err := m.CheckCSRF(r); err == nil {
		t.Fatal("expected invalid CSRF token")
	}
	w = httptest.NewRecorder()
	m.Logout(w)
	if w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
}

func TestLoginHandlerUsesNeutralError(t *testing.T) {
	m, _ := New(t.TempDir(), "/quiet", "admin", "secret")
	form := url.Values{"username": {"wrong"}, "password": {"wrong"}}
	r := httptest.NewRequest("POST", "https://example.com/quiet/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	m.LoginHandler("/quiet/login", "/quiet/").ServeHTTP(w, r)
	body, _ := io.ReadAll(w.Result().Body)
	if w.Code != 401 || !strings.Contains(string(body), "Не удалось войти") || strings.Contains(string(body), "Логин неверен") {
		t.Fatalf("code=%d body=%s", w.Code, body)
	}
}

func TestCredentialChangeInvalidatesSession(t *testing.T) {
	dir := t.TempDir()
	m1, _ := New(dir, "/quiet", "admin", "secret")
	w := httptest.NewRecorder()
	_, _ = m1.Login(w, "192.0.2.1:1", "admin", "secret")
	cookie := w.Result().Cookies()[0]
	m2, _ := New(dir, "/quiet", "admin", "changed")
	r := httptest.NewRequest("GET", "https://example.com/quiet", nil)
	r.AddCookie(cookie)
	if _, err := m2.Session(r); err == nil {
		t.Fatal("old session survived credential change")
	}
}

func TestLoginRateLimit(t *testing.T) {
	m, _ := New(t.TempDir(), "/quiet", "admin", "secret")
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < maxLoginTrials; i++ {
		if _, err := m.Login(httptest.NewRecorder(), "192.0.2.1:1", "bad", "bad"); err != ErrInvalidCredentials {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := m.Login(httptest.NewRecorder(), "192.0.2.1:1", "admin", "secret"); err != ErrRateLimited {
		t.Fatalf("expected rate limit, got %v", err)
	}
	now = now.Add(loginWindow + time.Second)
	if _, err := m.Login(httptest.NewRecorder(), "192.0.2.1:1", "admin", "secret"); err != nil {
		t.Fatalf("rate limit did not expire: %v", err)
	}
}
