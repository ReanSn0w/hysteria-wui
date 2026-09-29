package panel

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/ReanSn0w/hysteria-wui/internal/auth"
	"github.com/ReanSn0w/hysteria-wui/internal/clienturi"
	"github.com/ReanSn0w/hysteria-wui/internal/serverconfig"
	"github.com/skip2/go-qrcode"
)

//go:embed templates/*.html assets/* assets/vendor/*
var content embed.FS

type Config struct {
	BasePath string
	Auth     *auth.Manager
	Status   func() bool
	Store    *serverconfig.Store
	Restart  func() error
	Domain   string
}

type Handler struct {
	cfg       Config
	templates *template.Template
	assets    http.Handler
	mux       *http.ServeMux
}

type pageData struct {
	Title          string
	Base           string
	CSRF           string
	Running        bool
	Error          bool
	Message        string
	Users          []userRow
	User           string
	UserPath       string
	URI            string
	Config         string
	Editor         bool
	Sites          bool
	AccessRules    []serverconfig.AccessRule
	OtherACLCount  int
	SniffEnabled   bool
	AccessDisabled string
}

type userRow struct {
	Name string
	Path string
}

func New(cfg Config) (*Handler, error) {
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, err
	}
	assetFS, err := fs.Sub(content, "assets")
	if err != nil {
		return nil, err
	}
	h := &Handler{cfg: cfg, templates: tmpl, assets: http.FileServerFS(assetFS), mux: http.NewServeMux()}
	h.routes()
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	base := h.cfg.BasePath
	h.mux.Handle("GET "+base+"/assets/", http.StripPrefix(base+"/assets/", h.assets))
	h.mux.HandleFunc("GET "+base+"/login", h.loginPage)
	h.mux.HandleFunc("POST "+base+"/login", h.loginPage)
	h.mux.Handle("POST "+base+"/logout", h.cfg.Auth.LogoutHandler(base+"/login"))
	h.mux.Handle("GET "+base+"/", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+"/users", http.StatusSeeOther)
	})))
	h.mux.Handle("GET "+base+"/users", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.usersPage)))
	h.mux.Handle("POST "+base+"/users", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.addUser)))
	h.mux.Handle("POST "+base+"/users/delete", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.deleteUser)))
	h.mux.Handle("GET "+base+"/users/{name}/qr.png", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.userQR)))
	h.mux.Handle("GET "+base+"/users/{name}", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.userPage)))
	h.mux.Handle("GET "+base+"/config", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.configPage)))
	h.mux.Handle("GET "+base+"/sites", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.sitesPage)))
	h.mux.Handle("POST "+base+"/config", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.configPage)))
	h.mux.Handle("POST "+base+"/config/access", h.cfg.Auth.RequireSession(base+"/login", http.HandlerFunc(h.accessRules)))
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, err := h.cfg.Auth.Session(r); err == nil {
		http.Redirect(w, r, h.cfg.BasePath+"/users", http.StatusSeeOther)
		return
	}
	data := pageData{Title: "Вход", Base: h.cfg.BasePath}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if _, err := h.cfg.Auth.Login(w, r.RemoteAddr, r.Form.Get("username"), r.Form.Get("password")); err == nil {
				http.Redirect(w, r, h.cfg.BasePath+"/users", http.StatusSeeOther)
				return
			}
		}
		data.Error = true
		w.WriteHeader(http.StatusUnauthorized)
	}
	h.noStore(w)
	_ = h.templates.ExecuteTemplate(w, "login", data)
}

func (h *Handler) usersPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.cfg.Auth.Session(r)
	data := pageData{Title: "Пользователи", Base: h.cfg.BasePath, CSRF: session.CSRF, Running: h.cfg.Status != nil && h.cfg.Status(), Message: r.URL.Query().Get("message")}
	if h.cfg.Store == nil {
		data.Error = true
		data.Message = "Хранилище конфигурации не подключено."
	} else if users, err := h.cfg.Store.Users(); err != nil {
		data.Error = true
		data.Message = err.Error()
	} else {
		for _, user := range users {
			data.Users = append(data.Users, userRow{Name: user.Name, Path: url.PathEscape(user.Name)})
		}
	}
	h.noStore(w)
	_ = h.templates.ExecuteTemplate(w, "users", data)
}

func (h *Handler) addUser(w http.ResponseWriter, r *http.Request) {
	if err := h.cfg.Auth.CheckCSRF(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.Form.Get("name"))
	if h.cfg.Store == nil {
		h.redirectUsers(w, r, "Хранилище конфигурации не подключено.")
		return
	}
	password, err := generatedPassword()
	if err != nil {
		h.redirectUsers(w, r, "Не удалось сгенерировать пароль.")
		return
	}
	if err := h.cfg.Store.AddUser(name, password, h.cfg.Restart); err != nil {
		h.redirectUsers(w, r, "Не удалось создать пользователя: "+err.Error())
		return
	}
	http.Redirect(w, r, h.cfg.BasePath+"/users/"+url.PathEscape(name), http.StatusSeeOther)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := h.cfg.Auth.CheckCSRF(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if h.cfg.Store == nil {
		h.redirectUsers(w, r, "Хранилище конфигурации не подключено.")
		return
	}
	if err := h.cfg.Store.DeleteUser(r.Form.Get("name"), h.cfg.Restart); err != nil {
		h.redirectUsers(w, r, "Не удалось удалить пользователя: "+err.Error())
		return
	}
	h.redirectUsers(w, r, "Пользователь удалён.")
}

func (h *Handler) redirectUsers(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, h.cfg.BasePath+"/users?message="+url.QueryEscape(message), http.StatusSeeOther)
}

func generatedPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *Handler) userPage(w http.ResponseWriter, r *http.Request) {
	uri, user, err := h.userURI(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	session, _ := h.cfg.Auth.Session(r)
	data := pageData{
		Title: user.Name, Base: h.cfg.BasePath, CSRF: session.CSRF,
		Running: h.cfg.Status != nil && h.cfg.Status(), User: user.Name, UserPath: url.PathEscape(user.Name), URI: uri,
	}
	h.noStore(w)
	_ = h.templates.ExecuteTemplate(w, "user", data)
}

func (h *Handler) userQR(w http.ResponseWriter, r *http.Request) {
	uri, _, err := h.userURI(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	png, err := qrcode.Encode(uri, qrcode.Medium, 320)
	if err != nil {
		http.Error(w, "Could not generate QR code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Disposition", `inline; filename="hysteria-qr.png"`)
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

func (h *Handler) userURI(name string) (string, serverconfig.User, error) {
	if h.cfg.Store == nil {
		return "", serverconfig.User{}, http.ErrServerClosed
	}
	user, err := h.cfg.Store.User(name)
	if err != nil {
		return "", serverconfig.User{}, err
	}
	raw, err := h.cfg.Store.Read()
	if err != nil {
		return "", serverconfig.User{}, err
	}
	uri, err := clienturi.Build(h.cfg.Domain, user.Name, user.Password, raw)
	return uri, user, err
}

func (h *Handler) configPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Query().Get("tab") == "access" {
		http.Redirect(w, r, h.cfg.BasePath+"/sites", http.StatusSeeOther)
		return
	}
	session, _ := h.cfg.Auth.Session(r)
	data := pageData{
		Title: "Yaml", Base: h.cfg.BasePath, CSRF: session.CSRF, Editor: true,
		Running: h.cfg.Status != nil && h.cfg.Status(), Message: r.URL.Query().Get("message"), Error: r.URL.Query().Get("error") == "1",
	}
	if h.cfg.Store == nil {
		data.Error = true
		data.Message = "Хранилище конфигурации не подключено."
	} else if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		if err := h.cfg.Auth.CheckCSRF(r); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		data.Config = r.Form.Get("config")
		if err := h.cfg.Store.Save([]byte(data.Config), h.cfg.Restart); err != nil {
			data.Error = true
			data.Message = "Конфигурация не сохранена: " + err.Error()
		} else {
			http.Redirect(w, r, h.cfg.BasePath+"/config?message="+url.QueryEscape("Конфигурация сохранена, Hysteria перезапущена."), http.StatusSeeOther)
			return
		}
	} else if raw, err := h.cfg.Store.Read(); err != nil {
		data.Error = true
		data.Message = err.Error()
	} else {
		data.Config = string(raw)
	}
	h.noStore(w)
	_ = h.templates.ExecuteTemplate(w, "config", data)
}

func (h *Handler) sitesPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.cfg.Auth.Session(r)
	data := pageData{
		Title: "Сайты", Base: h.cfg.BasePath, CSRF: session.CSRF, Sites: true,
		Running: h.cfg.Status != nil && h.cfg.Status(), Message: r.URL.Query().Get("message"), Error: r.URL.Query().Get("error") == "1",
	}
	if h.cfg.Store == nil {
		data.Error = true
		data.Message = "Хранилище конфигурации не подключено."
		data.AccessDisabled = data.Message
	} else {
		h.populateAccessRules(&data)
	}
	h.noStore(w)
	_ = h.templates.ExecuteTemplate(w, "sites", data)
}

func (h *Handler) accessRules(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := h.cfg.Auth.CheckCSRF(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if h.cfg.Store == nil {
		http.Error(w, "Config store unavailable", http.StatusServiceUnavailable)
		return
	}
	current, err := h.cfg.Store.AccessRules()
	if err != nil {
		h.redirectSites(w, r, "Не удалось прочитать ACL: "+err.Error(), true)
		return
	}
	rules := append([]serverconfig.AccessRule(nil), current.Rules...)
	switch r.Form.Get("operation") {
	case "add":
		rules = append(rules, serverconfig.AccessRule{Action: r.Form.Get("action"), Domain: r.Form.Get("domain")})
	case "delete":
		var found bool
		rules, found = removeAccessRule(rules, r.Form.Get("action"), r.Form.Get("domain"))
		if !found {
			h.redirectSites(w, r, "Правило уже отсутствует.", true)
			return
		}
	case "reorder":
		actions, domains := r.Form["rule_action"], r.Form["rule_domain"]
		if len(actions) != len(domains) {
			h.redirectSites(w, r, "Некорректный порядок ACL.", true)
			return
		}
		rules = make([]serverconfig.AccessRule, len(actions))
		for i := range actions {
			rules[i] = serverconfig.AccessRule{Action: actions[i], Domain: domains[i]}
		}
		if !sameAccessRules(current.Rules, rules) {
			h.redirectSites(w, r, "Набор ACL-правил изменился; обновите страницу.", true)
			return
		}
	default:
		h.redirectSites(w, r, "Неизвестная ACL-операция.", true)
		return
	}
	if err := h.cfg.Store.SetAccessRules(rules, h.cfg.Restart); err != nil {
		h.redirectSites(w, r, "ACL не сохранён: "+err.Error(), true)
		return
	}
	h.redirectSites(w, r, "ACL сохранён, Hysteria перезапущена.", false)
}

func (h *Handler) populateAccessRules(data *pageData) {
	if h.cfg.Store == nil {
		return
	}
	rules, err := h.cfg.Store.AccessRules()
	if err != nil {
		data.AccessDisabled = err.Error()
		return
	}
	data.AccessRules = rules.Rules
	data.OtherACLCount = rules.OtherCount
	data.SniffEnabled = rules.SniffEnabled
}

func removeAccessRule(rules []serverconfig.AccessRule, action, domain string) ([]serverconfig.AccessRule, bool) {
	for i, rule := range rules {
		if rule.Action == action && rule.Domain == domain {
			return append(rules[:i], rules[i+1:]...), true
		}
	}
	return rules, false
}

func sameAccessRules(left, right []serverconfig.AccessRule) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[serverconfig.AccessRule]int, len(left))
	for _, rule := range left {
		counts[rule]++
	}
	for _, rule := range right {
		counts[rule]--
		if counts[rule] < 0 {
			return false
		}
	}
	return true
}

func (h *Handler) redirectSites(w http.ResponseWriter, r *http.Request, message string, failed bool) {
	values := url.Values{"message": {message}}
	if failed {
		values.Set("error", "1")
	}
	http.Redirect(w, r, h.cfg.BasePath+"/sites?"+values.Encode(), http.StatusSeeOther)
}

func (h *Handler) noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func IsAsset(path, base string) bool { return strings.HasPrefix(path, base+"/assets/") }
