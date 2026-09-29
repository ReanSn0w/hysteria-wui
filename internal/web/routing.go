package web

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-pkgz/lgr"
)

func NewPublicHandler(panelPath string, panel http.Handler, decoy *url.URL, log lgr.L) http.Handler {
	proxy := newDecoyProxy(decoy, log)
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := strings.ToLower(r.URL.EscapedPath())
		if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.Contains(r.URL.Path, "\\") {
			http.NotFound(w, r)
			return
		}
		isPanel := r.URL.Path == panelPath || strings.HasPrefix(r.URL.Path, panelPath+"/")
		if isPanel {
			if path.Clean(r.URL.Path) != strings.TrimSuffix(r.URL.Path, "/") && r.URL.Path != panelPath+"/" {
				http.NotFound(w, r)
				return
			}
			panel.ServeHTTP(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
}

func HTTPRedirect(domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + domain + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func newDecoyProxy(target *url.URL, log lgr.L) *httputil.ReverseProxy {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second, KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			req.SetXForwarded()
			req.Out.Host = target.Host
			for _, header := range []string{"Authorization", "Cookie", "X-CSRF-Token", "X-Forwarded-User"} {
				req.Out.Header.Del(header)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Logf("WARN decoy proxy request failed: %v", err)
			}
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}
	return proxy
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
