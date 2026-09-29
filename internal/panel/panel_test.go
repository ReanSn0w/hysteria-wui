package panel

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ReanSn0w/hysteria-wui/internal/auth"
	"github.com/ReanSn0w/hysteria-wui/internal/serverconfig"
	"github.com/liyue201/goqr"
)

func TestLoginAndProtectedPage(t *testing.T) {
	authManager, err := auth.New(t.TempDir(), "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{BasePath: "/quiet", Auth: authManager, Status: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://example.com/quiet/users", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/quiet/login" {
		t.Fatalf("code=%d location=%q", w.Code, w.Header().Get("Location"))
	}

	form := url.Values{"username": {"admin"}, "password": {"secret"}}
	r = httptest.NewRequest(http.MethodPost, "https://example.com/quiet/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || len(w.Result().Cookies()) != 1 {
		t.Fatalf("code=%d cookies=%d", w.Code, len(w.Result().Cookies()))
	}

	r = httptest.NewRequest(http.MethodGet, "https://example.com/quiet/users", nil)
	r.AddCookie(w.Result().Cookies()[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Hysteria работает") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUserPageAndQRRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, err := auth.New(dataDir, "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	const name, password = "alice @home", "p:a?ss#%"
	if err := store.AddUser(name, password, nil); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{BasePath: "/quiet", Auth: authManager, Store: store, Domain: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	_, _ = authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	cookie := login.Result().Cookies()[0]
	path := "/quiet/users/" + url.PathEscape(name)

	r := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hysteria2://") || !strings.Contains(w.Body.String(), "vpn.example.com") {
		t.Fatalf("page code=%d body=%s", w.Code, w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "https://example.com"+path+"/qr.png", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("QR code=%d headers=%v", w.Code, w.Header())
	}
	img, err := png.Decode(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	codes, err := goqr.Recognize(img)
	if err != nil || len(codes) != 1 {
		t.Fatalf("decode err=%v codes=%d", err, len(codes))
	}
	decoded, err := url.Parse(string(codes[0].Payload))
	if err != nil {
		t.Fatal(err)
	}
	gotPassword, _ := decoded.User.Password()
	if decoded.User.Username() != name || gotPassword != password || decoded.Host != "vpn.example.com:443" {
		t.Fatalf("decoded URI=%s", codes[0].Payload)
	}
}

func TestAddAndDeleteUser(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{
		Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org",
	})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, err := auth.New(dataDir, "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	h, err := New(Config{BasePath: "/quiet", Auth: authManager, Store: store, Restart: func() error { restarts++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	session, err := authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]

	form := url.Values{"csrf_token": {session.CSRF}, "name": {"alice"}, "password": {"must-be-ignored"}}
	r := httptest.NewRequest(http.MethodPost, "https://example.com/quiet/users", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/quiet/users/alice" {
		t.Fatalf("add code=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	users, err := store.Users()
	decodedPassword, decodeErr := base64.RawURLEncoding.DecodeString(users[0].Password)
	if err != nil || len(users) != 1 || users[0].Password == "must-be-ignored" || decodeErr != nil || len(decodedPassword) != 24 || restarts != 1 {
		t.Fatalf("users=%+v err=%v restarts=%d", users, err, restarts)
	}

	r = httptest.NewRequest(http.MethodGet, "https://example.com/quiet/users", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "alice") || strings.Contains(w.Body.String(), users[0].Password) {
		t.Fatalf("list leaked or omitted credentials: %s", w.Body.String())
	}

	form = url.Values{"csrf_token": {session.CSRF}, "name": {"alice"}}
	r = httptest.NewRequest(http.MethodPost, "https://example.com/quiet/users/delete", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	users, err = store.Users()
	if w.Code != http.StatusSeeOther || err != nil || len(users) != 0 || restarts != 2 {
		t.Fatalf("delete code=%d users=%+v err=%v restarts=%d", w.Code, users, err, restarts)
	}
}

func TestUserMutationRequiresCSRF(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, err := auth.New(dataDir, "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	_, _ = authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	h, _ := New(Config{BasePath: "/quiet", Auth: authManager, Store: store})
	r := httptest.NewRequest(http.MethodPost, "https://example.com/quiet/users", strings.NewReader("name=alice"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(login.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d", w.Code)
	}
}

func TestConfigEditorValidatesAndRestarts(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, err := auth.New(dataDir, "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	original, _ := store.Read()
	restarts := 0
	h, err := New(Config{BasePath: "/quiet", Auth: authManager, Store: store, Restart: func() error { restarts++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	session, _ := authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	cookie := login.Result().Cookies()[0]

	form := url.Values{"csrf_token": {session.CSRF}, "config": {"not: [valid"}}
	r := httptest.NewRequest(http.MethodPost, "https://example.com/quiet/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	afterInvalid, _ := store.Read()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "YAML syntax") || !bytes.Equal(original, afterInvalid) || restarts != 0 {
		t.Fatalf("invalid code=%d body=%s restarts=%d", w.Code, w.Body.String(), restarts)
	}

	valid := string(original) + "disableUDP: true\n"
	form = url.Values{"csrf_token": {session.CSRF}, "config": {valid}}
	r = httptest.NewRequest(http.MethodPost, "https://example.com/quiet/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	saved, _ := store.Read()
	if w.Code != http.StatusSeeOther || string(saved) != valid || restarts != 1 {
		t.Fatalf("valid code=%d location=%q saved=%q restarts=%d", w.Code, w.Header().Get("Location"), saved, restarts)
	}
}

func TestAccessRulesCRUDAndReorder(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, err := auth.New(dataDir, "/quiet", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	h, err := New(Config{BasePath: "/quiet", Auth: authManager, Store: store, Restart: func() error { restarts++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	session, _ := authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	cookie := login.Result().Cookies()[0]
	post := func(values url.Values) *httptest.ResponseRecorder {
		t.Helper()
		values.Set("csrf_token", session.CSRF)
		r := httptest.NewRequest(http.MethodPost, "https://example.com/quiet/config/access", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for _, values := range []url.Values{
		{"operation": {"add"}, "action": {"block"}, "domain": {".ru"}},
		{"operation": {"add"}, "action": {"allow"}, "domain": {"Rutracker.ru"}},
	} {
		w := post(values)
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/quiet/sites?") {
			t.Fatalf("add code=%d location=%q", w.Code, w.Header().Get("Location"))
		}
	}
	rules, err := store.AccessRules()
	if err != nil || len(rules.Rules) != 2 || rules.Rules[0].Action != "block" || rules.Rules[1].Domain != "rutracker.ru" || restarts != 2 {
		t.Fatalf("rules=%+v err=%v restarts=%d", rules, err, restarts)
	}

	w := post(url.Values{"operation": {"reorder"}, "rule_action": {"allow", "block"}, "rule_domain": {"rutracker.ru", "ru"}})
	rules, err = store.AccessRules()
	if w.Code != http.StatusSeeOther || err != nil || rules.Rules[0].Domain != "rutracker.ru" || rules.Rules[1].Domain != "ru" || restarts != 3 {
		t.Fatalf("reorder code=%d rules=%+v err=%v restarts=%d", w.Code, rules, err, restarts)
	}

	r := httptest.NewRequest(http.MethodGet, "https://example.com/quiet/sites", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "rutracker.ru") || !strings.Contains(w.Body.String(), "access-drag-handle") || !strings.Contains(w.Body.String(), "Сохранить порядок") || strings.Contains(w.Body.String(), "Например, разрешите") {
		t.Fatalf("access page code=%d body=%s", w.Code, w.Body.String())
	}
	nav := w.Body.String()
	usersPos, sitesPos, yamlPos := strings.Index(nav, ">Пользователи</a>"), strings.Index(nav, ">Сайты</a>"), strings.Index(nav, ">Yaml</a>")
	if usersPos < 0 || sitesPos <= usersPos || yamlPos <= sitesPos {
		t.Fatalf("navigation order: users=%d sites=%d yaml=%d", usersPos, sitesPos, yamlPos)
	}
	r = httptest.NewRequest(http.MethodGet, "https://example.com/quiet/config", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<h1 class=\"h3 mb-3\">Yaml</h1>") || strings.Contains(w.Body.String(), "access-rule-list") {
		t.Fatalf("yaml page code=%d body=%s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "https://example.com/quiet/config?tab=access", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/quiet/sites" {
		t.Fatalf("old access URL code=%d location=%q", w.Code, w.Header().Get("Location"))
	}

	w = post(url.Values{"operation": {"delete"}, "action": {"allow"}, "domain": {"rutracker.ru"}})
	rules, err = store.AccessRules()
	if w.Code != http.StatusSeeOther || err != nil || len(rules.Rules) != 1 || rules.Rules[0].Domain != "ru" || restarts != 4 {
		t.Fatalf("delete code=%d rules=%+v err=%v restarts=%d", w.Code, rules, err, restarts)
	}
}

func TestAccessRulesRequiresCSRF(t *testing.T) {
	dataDir := t.TempDir()
	store := serverconfig.NewStore(dataDir, serverconfig.Managed{Listen: ":8443", CertFile: "/data/cert.pem", KeyFile: "/data/key.pem", DecoyURL: "https://example.org"})
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	authManager, _ := auth.New(dataDir, "/quiet", "admin", "secret")
	login := httptest.NewRecorder()
	_, _ = authManager.Login(login, "127.0.0.1:1234", "admin", "secret")
	h, _ := New(Config{BasePath: "/quiet", Auth: authManager, Store: store})
	r := httptest.NewRequest(http.MethodPost, "https://example.com/quiet/config/access", strings.NewReader("operation=add&action=block&domain=ru"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(login.Result().Cookies()[0])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d", w.Code)
	}
}
