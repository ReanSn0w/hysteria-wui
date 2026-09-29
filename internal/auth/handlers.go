package auth

import (
	"html/template"
	"net/http"
)

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Вход · Hysteria WUI</title></head>
<body><main><h1>Hysteria WUI</h1>{{if .Error}}<p role="alert">Не удалось войти. Проверьте данные и повторите попытку.</p>{{end}}
<form method="post" action="{{.Action}}"><label>Логин <input name="username" autocomplete="username" required autofocus></label>
<label>Пароль <input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Войти</button></form>
</main></body></html>`))

func (m *Manager) LoginHandler(loginPath, successPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil {
				if _, err := m.Login(w, r.RemoteAddr, r.Form.Get("username"), r.Form.Get("password")); err == nil {
					http.Redirect(w, r, successPath, http.StatusSeeOther)
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			_ = loginTemplate.Execute(w, map[string]any{"Action": loginPath, "Error": true})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = loginTemplate.Execute(w, map[string]any{"Action": loginPath})
	})
}

func (m *Manager) LogoutHandler(redirectPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := m.CheckCSRF(r); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		m.Logout(w)
		http.Redirect(w, r, redirectPath, http.StatusSeeOther)
	})
}
