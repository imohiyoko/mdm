package webui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/internal/testkit"
)

type fakeAuth struct{ code string }

func (f fakeAuth) Start(context.Context) (string, string, string, error) {
	return "https://iam.example/authorize?x=1", "state-1", "verifier-1", nil
}

func (f fakeAuth) Exchange(_ context.Context, code, verifier string) (string, time.Duration, error) {
	if code != f.code || verifier != "verifier-1" {
		return "", 0, errors.New("bad code")
	}
	return "access-token", time.Hour, nil
}

func noRedirect() *http.Client {
	jar := &cookieJar{}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// cookieJar は Path を気にしない簡単な入れ物（テスト用）。
type cookieJar struct{ c map[string]*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cs []*http.Cookie) {
	if j.c == nil {
		j.c = map[string]*http.Cookie{}
	}
	for _, c := range cs {
		if c.MaxAge < 0 {
			delete(j.c, c.Name)
		} else {
			j.c[c.Name] = c
		}
	}
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range j.c {
		out = append(out, c)
	}
	return out
}

func TestLoginFlow(t *testing.T) {
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	ui := &UI{Auth: fakeAuth{code: "good"}, Clock: clock}
	srv := httptest.NewServer(ui.Handler())
	t.Cleanup(srv.Close)
	c := noRedirect()

	resp, err := c.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "app.js") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("index: %d %v", resp.StatusCode, resp.Header)
	}

	resp, _ = c.Get(srv.URL + "/ui/login")
	resp.Body.Close()
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), "https://iam.example/authorize") {
		t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// state が違えば断る。ログインのクッキーは 1 回で消える。
	resp, _ = c.Get(srv.URL + "/ui/callback?code=good&state=other")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("wrong state: %d", resp.StatusCode)
	}
	resp, _ = c.Get(srv.URL + "/ui/callback?code=good&state=state-1")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("ログインのクッキーは使い回せない: %d", resp.StatusCode)
	}
	c.Get(srv.URL + "/ui/login")
	resp, _ = c.Get(srv.URL + "/ui/callback?code=bad&state=state-1")
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("bad code: %d", resp.StatusCode)
	}
	c.Get(srv.URL + "/ui/login")
	resp, _ = c.Get(srv.URL + "/ui/callback?code=good&state=state-1")
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/ui/" {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	sess := c.Jar.(*cookieJar).c[sessionCookie]
	if sess == nil || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie: %+v", sess)
	}

	req := httptest.NewRequest("GET", "/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Value})
	if _, ok := ui.Token(req); ok {
		t.Fatal("X-MDM-UI が無ければ使えない（CSRF）")
	}
	req.Header.Set(Header, "1")
	if tok, ok := ui.Token(req); !ok || tok != "access-token" {
		t.Fatal(tok, ok)
	}
	bad := httptest.NewRequest("GET", "/v1/me", nil)
	bad.Header.Set(Header, "1")
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: "guess"})
	if _, ok := ui.Token(bad); ok {
		t.Fatal("知らないセッション")
	}

	// ログアウトはヘッダーが要る。したら使えない。
	lo, _ := http.NewRequest("POST", srv.URL+"/ui/logout", nil)
	resp, _ = c.Do(lo)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("logout without header: %d", resp.StatusCode)
	}
	lo, _ = http.NewRequest("POST", srv.URL+"/ui/logout", nil)
	lo.Header.Set(Header, "1")
	resp, _ = c.Do(lo)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if _, ok := ui.Token(req); ok {
		t.Fatal("ログアウトしたら使えない")
	}

	// 期限が切れたら使えない。
	id := ui.newSession("t2", time.Minute)
	r2 := httptest.NewRequest("GET", "/v1/me", nil)
	r2.Header.Set(Header, "1")
	r2.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	clock.Advance(2 * time.Minute)
	if _, ok := ui.Token(r2); ok {
		t.Fatal("期限切れ")
	}
}
