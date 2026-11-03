package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Login は管理画面のログイン（認可コードフローと PKCE）。MDM が機密クライアントとしてコードをトークンに換えるので、
// アクセストークンはブラウザーに渡らない（管理画面のサーバー側のセッションに置く）。
type Login struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL は IAM に登録した戻り先（https://admin.example/ui/callback）。
	RedirectURL string
	HTTP        *http.Client

	mu       sync.Mutex
	authz    string
	tokenURL string
}

func (l *Login) http() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (l *Login) endpoints(ctx context.Context) (string, string, error) {
	l.mu.Lock()
	a, t := l.authz, l.tokenURL
	l.mu.Unlock()
	if a != "" && t != "" {
		return a, t, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(l.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := l.http().Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var d struct {
		Issuer string `json:"issuer"`
		Authz  string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return "", "", err
	}
	if d.Issuer != l.Issuer {
		return "", "", fmt.Errorf("discovery: issuer %q does not match %q", d.Issuer, l.Issuer)
	}
	for _, e := range []string{d.Authz, d.Token} {
		if u, err := url.Parse(e); err != nil || u.Scheme != "https" {
			return "", "", errors.New("discovery: authorization_endpoint と token_endpoint は https")
		}
	}
	l.mu.Lock()
	l.authz, l.tokenURL = d.Authz, d.Token
	l.mu.Unlock()
	return d.Authz, d.Token, nil
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start はログインを始める。state と verifier は呼んだ側がブラウザーの短いクッキーに置き、戻ってきたときに比べる。
func (l *Login) Start(ctx context.Context) (redirect, state, verifier string, err error) {
	authz, _, err := l.endpoints(ctx)
	if err != nil {
		return "", "", "", err
	}
	state, verifier = random(), random()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {l.ClientID},
		"redirect_uri":          {l.RedirectURL},
		"scope":                 {"openid"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(authz, "?") {
		sep = "&"
	}
	return authz + sep + q.Encode(), state, verifier, nil
}

// Exchange はコードをアクセストークンに換える。
func (l *Login) Exchange(ctx context.Context, code, verifier string) (token string, expiresIn time.Duration, err error) {
	_, tokenURL, err := l.endpoints(ctx)
	if err != nil {
		return "", 0, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {l.RedirectURL}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(l.ClientID), url.QueryEscape(l.ClientSecret))
	resp, err := l.http().Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", 0, err
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" || !strings.EqualFold(body.TokenType, "bearer") {
		return "", 0, fmt.Errorf("token: status %d %s", resp.StatusCode, body.Error)
	}
	exp := time.Duration(body.ExpiresIn) * time.Second
	if exp <= 0 || exp > 12*time.Hour {
		exp = time.Hour
	}
	return body.AccessToken, exp, nil
}
