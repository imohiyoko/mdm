package oidcauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestIntrospect(t *testing.T) {
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "introspection_endpoint": srv.URL + "/introspect"})
		case "/introspect":
			calls.Add(1)
			id, secret, ok := r.BasicAuth()
			if !ok || id != "mdm" || secret != "s3cret" {
				http.Error(w, "unauthorized", 401)
				return
			}
			_ = r.ParseForm()
			exp := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC).Unix()
			switch r.PostForm.Get("token") {
			case "good":
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "iss": srv.URL, "aud": []string{"mdm", "x"}, "email": "a@example.com", "exp": exp})
			case "other-aud":
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "aud": "other", "exp": exp})
			case "other-iss":
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "u1", "iss": "https://evil.example", "aud": "mdm", "exp": exp})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
			}
		}
	}))
	defer srv.Close()
	clock := testkit.NewClock(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	c := &Client{Issuer: srv.URL, ClientID: "mdm", ClientSecret: "s3cret", Audience: "mdm", HTTP: srv.Client(), Clock: clock}
	ctx := context.Background()

	in, err := c.Introspect(ctx, "good")
	if err != nil || !in.Active || in.Subject != "u1" || in.Issuer != srv.URL || in.Username != "a@example.com" {
		t.Fatalf("good: %+v %v", in, err)
	}
	if _, _ = c.Introspect(ctx, "good"); calls.Load() != 1 {
		t.Fatalf("覚えた答えを使う: %d", calls.Load())
	}
	for _, tok := range []string{"other-aud", "other-iss", "revoked"} {
		if in, err := c.Introspect(ctx, tok); err != nil || in.Active {
			t.Errorf("%s: %+v %v", tok, in, err)
		}
	}
	// 期限が過ぎたら、覚えた答えも使わない。
	clock.Advance(2 * time.Hour)
	if in, _ := c.Introspect(ctx, "good"); in.Active {
		t.Fatal("期限切れ")
	}

	bad := &Client{Issuer: srv.URL, ClientID: "mdm", ClientSecret: "wrong", HTTP: srv.Client(), Clock: clock}
	if _, err := bad.Introspect(ctx, "good"); err == nil {
		t.Fatal("連携先の認証に失敗したらエラー")
	}
	mismatch := &Client{Issuer: "https://iam.example", ClientID: "mdm", ClientSecret: "s3cret", HTTP: srv.Client(), Clock: clock}
	mismatch.Issuer = srv.URL + "/"
	if _, err := mismatch.Introspect(ctx, "good"); err == nil {
		t.Fatal("Discovery の issuer が違えばエラー")
	}
}
