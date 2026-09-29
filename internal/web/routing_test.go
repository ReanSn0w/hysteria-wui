package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type discardLog struct{}

func (discardLog) Logf(string, ...interface{}) {}

func TestPublicHandler(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("sensitive headers leaked upstream")
		}
		if r.Host != upstreamHost {
			t.Errorf("host was not rewritten: %q", r.Host)
		}
		w.Header().Set("Set-Cookie", "upstream=bad")
		_, _ = io.WriteString(w, "decoy:"+r.URL.Path)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	upstreamHost = target.Host
	proxy := newDecoyProxy(target, discardLog{})
	transport := proxy.Transport.(*http.Transport)
	if transport.ResponseHeaderTimeout <= 0 || transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("reverse proxy timeouts must be bounded")
	}
	panel := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "panel") })
	handler := NewPublicHandler("/quiet", panel, target, discardLog{})

	for requestPath, want := range map[string]string{"/quiet/users": "panel", "/": "decoy:/", "/news": "decoy:/news"} {
		r := httptest.NewRequest(http.MethodGet, "https://public.example"+requestPath, nil)
		r.Header.Set("Authorization", "secret")
		r.Header.Set("Cookie", "session=secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != want {
			t.Fatalf("%s: code=%d body=%q", requestPath, w.Code, w.Body.String())
		}
		if requestPath != "/quiet/users" && w.Header().Get("Set-Cookie") != "" {
			t.Fatal("upstream cookie was not stripped")
		}
	}

	for _, requestPath := range []string{"/quiet/../users", "/quiet%2fusers"} {
		r := httptest.NewRequest(http.MethodGet, "https://public.example"+requestPath, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: code=%d", requestPath, w.Code)
		}
	}
}

func TestHTTPRedirect(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://old.example/path?q=1", nil)
	w := httptest.NewRecorder()
	HTTPRedirect("vpn.example.com").ServeHTTP(w, r)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://vpn.example.com/path?q=1" {
		t.Fatalf("code=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}
