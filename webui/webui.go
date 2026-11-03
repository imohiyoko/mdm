// Package webui は管理画面。画面そのもの（HTML・JS・CSS）と、IAM でのログイン（認可コードフロー）を受け持つ。
//
// アクセストークンはブラウザーに渡さない。MDM がコードをトークンに換え、サーバーのメモリーのセッションに置き、
// ブラウザーには推測できないセッションの id だけを HttpOnly のクッキーで渡す。管理の API はクッキーを、
// X-MDM-UI ヘッダーの付いた要求でだけ受ける（ほかのサイトからはこのヘッダーを付けて送れないので、CSRF を防ぐ）。
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
)

//go:embed static
var static embed.FS

// Authenticator は IAM でのログイン（oidcauth.Login）。
type Authenticator interface {
	Start(ctx context.Context) (redirect, state, verifier string, err error)
	Exchange(ctx context.Context, code, verifier string) (token string, expiresIn time.Duration, err error)
}

const (
	sessionCookie = "mdm_ui"
	loginCookie   = "mdm_ui_login"
	// Header は管理画面が API に付けるヘッダー。
	Header      = "X-MDM-UI"
	maxSessions = 10000
)

type session struct {
	token string
	exp   time.Time
}

// UI は管理画面。
type UI struct {
	Auth  Authenticator
	Clock core.Clock
	// Secure はクッキーに Secure を付けるか（管理の入り口が https のとき）。
	Secure bool
	Logger *slog.Logger

	mu       sync.Mutex
	sessions map[string]session
}

func (u *UI) log() *slog.Logger {
	if u.Logger == nil {
		return slog.Default()
	}
	return u.Logger
}

func randomID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Token は管理画面からの要求のアクセストークン（adminapi.Server.UI）。
func (u *UI) Token(r *http.Request) (string, bool) {
	if r.Header.Get(Header) != "1" {
		return "", false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	s, ok := u.sessions[c.Value]
	if !ok || !u.Clock.Now().Before(s.exp) {
		delete(u.sessions, c.Value)
		return "", false
	}
	return s.token, true
}

func (u *UI) newSession(token string, ttl time.Duration) string {
	id := randomID()
	now := u.Clock.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sessions == nil {
		u.sessions = map[string]session{}
	}
	if len(u.sessions) >= maxSessions {
		for k, s := range u.sessions {
			if !now.Before(s.exp) {
				delete(u.sessions, k)
			}
		}
		if len(u.sessions) >= maxSessions {
			for k := range u.sessions { // それでも多ければ、どれかを捨てる（その人はログインし直す）
				delete(u.sessions, k)
				break
			}
		}
	}
	u.sessions[id] = session{token: token, exp: now.Add(ttl)}
	return id
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

// Handler は /ui/ 以下。
func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	files, _ := fs.Sub(static, "static")
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(files)))
	mux.HandleFunc("GET /ui/", func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /ui/login", u.login)
	mux.HandleFunc("GET /ui/callback", u.callback)
	mux.HandleFunc("POST /ui/logout", u.logout)
	return mux
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	secureHeaders(w)
	redirect, state, verifier, err := u.Auth.Start(r.Context())
	if err != nil {
		u.log().Error("ui login", "err", err)
		http.Error(w, "IAM につながらない", http.StatusBadGateway)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: state + "." + verifier, Path: "/ui/callback", MaxAge: 600,
		HttpOnly: true, Secure: u.Secure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (u *UI) callback(w http.ResponseWriter, r *http.Request) {
	secureHeaders(w)
	c, err := r.Cookie(loginCookie)
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Path: "/ui/callback", MaxAge: -1, HttpOnly: true, Secure: u.Secure, SameSite: http.SameSiteLaxMode})
	if err != nil {
		http.Error(w, "ログインをやり直す", http.StatusBadRequest)
		return
	}
	state, verifier, ok := strings.Cut(c.Value, ".")
	got := r.URL.Query().Get("state")
	if !ok || got == "" || subtle.ConstantTimeCompare([]byte(state), []byte(got)) != 1 {
		http.Error(w, "ログインをやり直す", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "ログインできなかった", http.StatusBadRequest)
		return
	}
	token, ttl, err := u.Auth.Exchange(r.Context(), code, verifier)
	if err != nil {
		u.log().Warn("ui token", "err", err)
		http.Error(w, "ログインできなかった", http.StatusBadGateway)
		return
	}
	id := u.newSession(token, ttl)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: u.Secure, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(Header) != "1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		u.mu.Lock()
		delete(u.sessions, c.Value)
		u.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: u.Secure, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}
