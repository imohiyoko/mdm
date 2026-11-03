// Package oidcauth は IAM（OIDC の IdP）のアクセストークンをイントロスペクション（RFC 7662）で確かめる。
// iam のアクセストークンは不透明トークン（iam の ADR 0021）なので、署名ではなく問い合わせで確かめる。
package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
)

// Client は introspection_endpoint に client_secret_basic で問い合わせる。
type Client struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// Audience が空でなければ、トークンの aud にこれが含まれることを求める（ほかの連携先のトークンを使わせない）。
	Audience string
	// Endpoint が空なら Issuer の /.well-known/openid-configuration から引く。
	Endpoint string
	HTTP     *http.Client
	Clock    core.Clock
	// CacheTTL は答えを覚えておく時間（既定 30 秒）。失効の反映はこの分だけ遅れる。
	CacheTTL time.Duration

	mu    sync.Mutex
	cache map[[32]byte]cached
}

type cached struct {
	in  adminapi.Introspection
	exp time.Time
}

const maxCache = 1000

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c *Client) ttl() time.Duration {
	if c.CacheTTL == 0 {
		return 30 * time.Second
	}
	return c.CacheTTL
}

func (c *Client) endpoint(ctx context.Context) (string, error) {
	c.mu.Lock()
	ep := c.Endpoint
	c.mu.Unlock()
	if ep != "" {
		return ep, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var d struct {
		Issuer        string `json:"issuer"`
		Introspection string `json:"introspection_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return "", err
	}
	if d.Issuer != c.Issuer {
		return "", fmt.Errorf("discovery: issuer %q does not match %q", d.Issuer, c.Issuer)
	}
	if u, err := url.Parse(d.Introspection); err != nil || u.Scheme != "https" {
		return "", errors.New("discovery: introspection_endpoint must be https")
	}
	c.mu.Lock()
	c.Endpoint = d.Introspection
	c.mu.Unlock()
	return d.Introspection, nil
}

// Introspect はトークンを確かめる。無効なトークンは Active: false（エラーではない）。
func (c *Client) Introspect(ctx context.Context, token string) (adminapi.Introspection, error) {
	key := sha256.Sum256([]byte(token))
	now := c.Clock.Now()
	c.mu.Lock()
	if v, ok := c.cache[key]; ok && now.Before(v.exp) {
		c.mu.Unlock()
		return v.in, nil
	}
	c.mu.Unlock()

	ep, err := c.endpoint(ctx)
	if err != nil {
		return adminapi.Introspection{}, err
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	if err != nil {
		return adminapi.Introspection{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := c.http().Do(req)
	if err != nil {
		return adminapi.Introspection{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return adminapi.Introspection{}, fmt.Errorf("introspection: status %d", resp.StatusCode)
	}
	var body struct {
		Active   bool            `json:"active"`
		Iss      string          `json:"iss"`
		Sub      string          `json:"sub"`
		Username string          `json:"username"`
		Email    string          `json:"email"`
		Exp      int64           `json:"exp"`
		Aud      json.RawMessage `json:"aud"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return adminapi.Introspection{}, err
	}
	in := adminapi.Introspection{Active: body.Active, Issuer: c.Issuer, Subject: body.Sub, Username: body.Username}
	if in.Username == "" {
		in.Username = body.Email
	}
	switch {
	case !body.Active:
		in = adminapi.Introspection{}
	case body.Iss != "" && body.Iss != c.Issuer:
		in = adminapi.Introspection{}
	case body.Exp != 0 && !now.Before(time.Unix(body.Exp, 0)):
		in = adminapi.Introspection{}
	case c.Audience != "" && !hasAudience(body.Aud, c.Audience):
		in = adminapi.Introspection{}
	}
	exp := now.Add(c.ttl())
	if in.Active && body.Exp != 0 && time.Unix(body.Exp, 0).Before(exp) {
		exp = time.Unix(body.Exp, 0)
	}
	c.mu.Lock()
	if c.cache == nil || len(c.cache) >= maxCache {
		c.cache = map[[32]byte]cached{}
	}
	c.cache[key] = cached{in, exp}
	c.mu.Unlock()
	return in, nil
}

func hasAudience(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
