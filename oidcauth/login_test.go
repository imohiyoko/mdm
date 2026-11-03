package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLogin(t *testing.T) {
	var issuer string
	var challenge string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token"})
		case "/token":
			id, sec, _ := r.BasicAuth()
			_ = r.ParseForm()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if id != "mdm" || sec != "s" || r.Form.Get("code") != "c1" || r.Form.Get("redirect_uri") != "https://admin.example/ui/callback" ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 600})
		}
	}))
	t.Cleanup(srv.Close)
	issuer = srv.URL
	l := &Login{Issuer: issuer, ClientID: "mdm", ClientSecret: "s", RedirectURL: "https://admin.example/ui/callback", HTTP: srv.Client()}
	ctx := context.Background()
	redirect, state, verifier, err := l.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if !strings.HasSuffix(u.Path, "/authorize") || q.Get("state") != state || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "mdm" || q.Get("scope") != "openid" {
		t.Fatal(redirect)
	}
	challenge = q.Get("code_challenge")
	tok, exp, err := l.Exchange(ctx, "c1", verifier)
	if err != nil || tok != "at" || exp != 10*time.Minute {
		t.Fatal(tok, exp, err)
	}
	if _, _, err := l.Exchange(ctx, "c1", "wrong-verifier"); err == nil {
		t.Fatal("違う verifier")
	}
}
