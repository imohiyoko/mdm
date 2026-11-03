// mdm は家庭・小さな組織向けの端末管理のサーバー。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/config"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/oidcauth"
	"github.com/imohiyoko/mdm/resolver"
	"github.com/imohiyoko/mdm/storage/sqlite"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		path := fs.String("config", "mdm.yaml", "設定ファイル")
		_ = fs.Parse(os.Args[2:])
		if err := serve(*path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "admin-token":
		adminToken()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "使い方: mdm serve -config mdm.yaml | mdm admin-token")
	os.Exit(2)
}

// adminToken は管理の API の鍵を作り、鍵と、設定に書く SHA-256 を出す。
func adminToken() {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := "mdm_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(tok))
	fmt.Printf("鍵（管理の API で Authorization: Bearer に使う。ここでしか表示しない）:\n  %s\n設定の admin.tokens に書く sha256:\n  %s\n", tok, hex.EncodeToString(sum[:]))
}

func serve(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := sqlite.Open(ctx, cfg.Storage.SQLite)
	if err != nil {
		return err
	}
	defer store.Close()
	clock := core.SystemClock{}
	if err := ensureDefaultPolicy(ctx, store, clock); err != nil {
		return err
	}

	engine := &filter.Engine{
		Store:       store,
		Clock:       clock,
		AlwaysAllow: filter.NewDomainSet(append([]string{cfg.PublicHost()}, cfg.Filter.AlwaysAllow...)),
		Logger:      logger,
	}
	var upstream resolver.Upstream
	if cfg.Upstream.Plain != "" {
		upstream = &resolver.PlainUpstream{Addr: cfg.Upstream.Plain}
	} else {
		upstream = &resolver.DoHUpstream{URL: cfg.Upstream.DoH, Client: &http.Client{Timeout: 5 * time.Second}}
	}
	qlog := &resolver.QueryLogger{Store: store, Clock: clock, Logger: logger}
	res := &resolver.Resolver{Engine: engine, Upstream: upstream, Log: qlog, Logger: logger}
	refresher := &blocklist.Refresher{Store: store, Clock: clock, OnChange: engine.Invalidate, Logger: logger}

	admin := &adminapi.Server{
		Store: store, Clock: clock, Engine: engine, Refresher: refresher, Tokens: cfg.Admin.Tokens, Logger: logger,
		Endpoints: adminapi.FilterEndpoints{DoHBaseURL: cfg.Public.BaseURL, DoTDomain: cfg.DoT.Domain},
	}
	if o := cfg.OIDC; o.Issuer != "" {
		admin.Issuer = o.Issuer
		admin.Introspector = &oidcauth.Client{
			Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret, Audience: o.Audience,
			Endpoint: o.IntrospectionEndpoint, Clock: clock,
		}
	}
	if cfg.DoT.Listen == "" {
		admin.Endpoints.DoTDomain = ""
	}
	public := &resolver.PublicHandler{Resolver: res, DoHBaseURL: cfg.Public.BaseURL}
	publicMux := http.NewServeMux()
	publicMux.Handle("/", public.Handler())

	if cfg.AndroidEnabled() {
		key, err := os.ReadFile(cfg.Android.CredentialsFile)
		if err != nil {
			return fmt.Errorf("android.credentials_file: %w", err)
		}
		client, err := android.NewClient(ctx, key)
		if err != nil {
			return err
		}
		svc := &android.Service{
			Store: store, Client: client, Engine: engine, Clock: clock, ProjectID: cfg.Android.ProjectID,
			CallbackURL: cfg.Public.BaseURL + android.CallbackPath, DoTDomain: admin.Endpoints.DoTDomain, Logger: logger,
		}
		admin.Android = svc
		publicMux.Handle(android.CallbackPath, svc.CallbackHandler())
		go svc.Run(ctx, cfg.Android.SyncInterval)
	}

	errc := make(chan error, 4)
	servers := []*http.Server{
		{Addr: cfg.Admin.Listen, Handler: admin.Handler(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: cfg.Public.Listen, Handler: publicMux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute},
	}
	go func() { errc <- listen(servers[0], cfg.Admin.TLS) }()
	go func() { errc <- listen(servers[1], cfg.Public.TLS) }()

	if cfg.DoT.Listen != "" {
		cert, err := tls.LoadX509KeyPair(cfg.DoT.TLS.Cert, cfg.DoT.TLS.Key)
		if err != nil {
			return fmt.Errorf("dot.tls: %w", err)
		}
		ln, err := net.Listen("tcp", cfg.DoT.Listen)
		if err != nil {
			return err
		}
		dot := &resolver.DoTServer{Resolver: res, Domain: cfg.DoT.Domain, Logger: logger,
			TLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		go func() { errc <- dot.Serve(ctx, ln) }()
	}

	go qlog.Run(ctx, 2*time.Second)
	go every(ctx, time.Hour, func() {
		n, err := store.DeleteQueryLogsBefore(ctx, clock.Now().AddDate(0, 0, -cfg.Filter.QueryLogRetentionDays))
		if err != nil {
			logger.Error("query log retention", "err", err)
		} else if n > 0 {
			logger.Info("query log retention", "deleted", n)
		}
	})
	go func() {
		refresher.RefreshAll(ctx)
		every(ctx, cfg.Blocklists.RefreshInterval, func() { refresher.RefreshAll(ctx) })
	}()

	logger.Info("started", "admin", cfg.Admin.Listen, "public", cfg.Public.Listen, "dot", cfg.DoT.Listen)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil {
			stop()
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	return qlog.Flush(shutdown)
}

func listen(s *http.Server, t config.TLS) error {
	var err error
	if t.Enabled() {
		s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = s.ListenAndServeTLS(t.Cert, t.Key)
	} else {
		err = s.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

func ensureDefaultPolicy(ctx context.Context, store core.Store, clock core.Clock) error {
	_, err := store.GetPolicy(ctx, filter.DefaultPolicyID)
	if !errors.Is(err, core.ErrNotFound) {
		return err
	}
	return store.CreatePolicy(ctx, core.Policy{
		ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist, UpdatedAt: clock.Now(),
	})
}
