// mdm は家庭・小さな組織向けの端末管理のサーバー。
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"syscall"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/apple"
	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/config"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/network"
	"github.com/imohiyoko/mdm/oidcauth"
	"github.com/imohiyoko/mdm/pki"
	"github.com/imohiyoko/mdm/radiusd"
	"github.com/imohiyoko/mdm/resolver"
	"github.com/imohiyoko/mdm/ssf"
	"github.com/imohiyoko/mdm/storage/sqlite"
	"github.com/imohiyoko/mdm/webui"
	"github.com/imohiyoko/mdm/windows"
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
		AlwaysAllow: filter.NewDomainSet(append(cfg.AllowHosts(), cfg.Filter.AlwaysAllow...)),
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
		Limits:    core.OrgLimits{Devices: cfg.Limits.Devices, People: cfg.Limits.People, Groups: cfg.Limits.Groups, Policies: cfg.Limits.Policies},
	}
	if o := cfg.OIDC; o.Issuer != "" {
		admin.Issuer = o.Issuer
		admin.Introspector = &oidcauth.Client{
			Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret, Audience: o.Audience,
			Endpoint: o.IntrospectionEndpoint, Clock: clock,
		}
		admin.Signup = adminapi.Signup{Enabled: cfg.Signup.Enabled, MaxOrgsPerUser: cfg.Signup.MaxOrgsPerUser}
	}
	if cfg.DoT.Listen == "" {
		admin.Endpoints.DoTDomain = ""
	}
	public := &resolver.PublicHandler{Resolver: res, DoHBaseURL: cfg.Public.BaseURL}
	publicMux := http.NewServeMux()
	publicMux.Handle("/", public.Handler())

	// 端末の準拠の判定と、IAM などへの知らせ（SSF）。
	// 受け手は設定に書いたものと、組織の管理者が API で登録したもの。
	var transmitter *ssf.Transmitter
	{
		signer, err := ssf.LoadOrCreateSigner(cfg.SSF.SigningKey)
		if err != nil {
			return fmt.Errorf("ssf.signing_key: %w", err)
		}
		transmitter = &ssf.Transmitter{Store: store, Clock: clock, Signer: signer, Issuer: cfg.Public.BaseURL, Logger: logger,
			Dynamic: func(ctx context.Context) ([]ssf.Receiver, error) {
				rs, err := store.ListSSFReceivers(ctx, "")
				if err != nil {
					return nil, err
				}
				out := make([]ssf.Receiver, 0, len(rs))
				for _, r := range rs {
					out = append(out, ssf.Receiver{Name: r.ID, URL: r.URL, PushToken: r.PushToken, Audience: r.Audience,
						OrgIDs: []string{r.OrgID}, Untrusted: true})
				}
				return out, nil
			}}
		for _, r := range cfg.SSF.Receivers {
			tok, err := os.ReadFile(r.PushTokenFile)
			if err != nil {
				return fmt.Errorf("ssf.receivers %s: %w", r.Name, err)
			}
			transmitter.Receivers = append(transmitter.Receivers, ssf.Receiver{Name: r.Name, URL: r.URL,
				PushToken: strings.TrimSpace(string(tok)), Audience: r.Audience, OrgIDs: []string(r.OrgIDs)})
		}
		publicMux.Handle("/.well-known/", transmitter.Handler())
	}
	errc := make(chan error, 8)
	if cfg.RADIUSEnabled() {
		rc := cfg.RADIUS
		ca, err := pki.LoadOrCreateNetworkCA(rc.CACert, rc.CAKey, "mdm network CA", rc.ServerName)
		if err != nil {
			return fmt.Errorf("radius の認証局: %w", err)
		}
		admin.Network = &network.Service{Store: store, Clock: clock, CA: ca, ServerName: rc.ServerName}
		// サーバーの証明書は起動のたびに作る（端末は認証局と名前で確かめるので、入れ替えても困らない）。
		skey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		scert, err := ca.IssueServer(&skey.PublicKey, rc.ServerName, clock.Now(), 2*365*24*time.Hour)
		if err != nil {
			return err
		}
		rs := &radiusd.Server{Store: store, Clock: clock, CA: ca, RequireCompliant: rc.RequireCompliant, Logger: logger,
			TLSCert: tls.Certificate{Certificate: [][]byte{scert.Raw, ca.Cert.Raw}, PrivateKey: skey, Leaf: scert}}
		for _, cl := range rc.Clients {
			sec, err := os.ReadFile(cl.SecretFile)
			if err != nil {
				return fmt.Errorf("radius.clients %s: %w", cl.Name, err)
			}
			sec = bytes.TrimSpace(sec)
			if len(sec) < 16 {
				return fmt.Errorf("radius.clients %s: 共有の秘密は 16 文字以上にする", cl.Name)
			}
			prefix, _ := config.ParseClientAddress(cl.Address)
			rs.Clients = append(rs.Clients, radiusd.Client{Name: cl.Name, Prefix: prefix, Secret: sec, OrgIDs: []string(cl.OrgIDs)})
			admin.StaticRADIUSPrefixes = append(admin.StaticRADIUSPrefixes, prefix)
		}
		// 組織の管理者が API で登録したルーター。名前は設定のものと重ならないように "org:" を付ける。
		rs.Dynamic = func(ctx context.Context) ([]radiusd.Client, error) {
			cs, err := store.ListRADIUSClients(ctx, "")
			if err != nil {
				return nil, err
			}
			out := make([]radiusd.Client, 0, len(cs))
			for _, c := range cs {
				rc := radiusd.Client{Name: "org:" + c.OrgID + "/" + c.ID, Prefix: c.Prefix, Secret: []byte(c.Secret), OrgIDs: []string{c.OrgID}}
				if c.CertFingerprint != "" {
					rc.RadSecID, rc.RadSecFingerprint = c.ID, c.CertFingerprint
				}
				out = append(out, rc)
			}
			return out, nil
		}
		admin.RADIUSChanged = func() {
			if err := rs.Refresh(ctx); err != nil {
				logger.Error("radius refresh", "err", err)
			}
		}
		pc, err := net.ListenPacket("udp", rc.Listen)
		if err != nil {
			return fmt.Errorf("radius.listen: %w", err)
		}
		go func() { errc <- rs.Serve(ctx, pc) }()
		if rc.RadSecListen != "" {
			rca, err := pki.LoadOrCreateCA(rc.RadSecCACert, rc.RadSecCAKey, "mdm RadSec router CA")
			if err != nil {
				return fmt.Errorf("radius の RadSec の認証局: %w", err)
			}
			rs.RadSecCA = rca
			admin.RadSec = &adminapi.RadSec{CA: rca, Address: rc.RadSecAddress}
			ln, err := tls.Listen("tcp", rc.RadSecListen, rs.RadSecTLS(rca))
			if err != nil {
				return fmt.Errorf("radius.radsec_listen: %w", err)
			}
			go func() { errc <- rs.ServeRadSec(ctx, ln) }()
		}
	}
	comp := &compliance.Service{Store: store, Engine: engine, Clock: clock, Transmitter: transmitter, Logger: logger}
	admin.Compliance = comp
	go comp.Run(ctx, cfg.Compliance.Interval)

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

	adminHandler := admin.Handler()
	if cfg.Admin.BaseURL != "" {
		o := cfg.OIDC
		ui := &webui.UI{
			Auth:  &oidcauth.Login{Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: cfg.Admin.BaseURL + "/ui/callback"},
			Clock: clock, Secure: strings.HasPrefix(cfg.Admin.BaseURL, "https://"), Logger: logger,
		}
		admin.UI = ui
		mux := http.NewServeMux()
		mux.Handle("/ui/", ui.Handler())
		mux.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
		mux.Handle("/", adminHandler)
		adminHandler = mux
	}
	servers := []*http.Server{
		{Addr: cfg.Admin.Listen, Handler: adminHandler, ReadHeaderTimeout: 10 * time.Second},
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

	if cfg.WindowsEnabled() {
		ca, err := pki.LoadOrCreateCA(cfg.Windows.CACert, cfg.Windows.CAKey, "mdm Windows device CA")
		if err != nil {
			return fmt.Errorf("windows の認証局: %w", err)
		}
		svc := &windows.Service{
			Store: store, Engine: engine, Clock: clock, CA: ca, BaseURL: cfg.Windows.BaseURL,
			PollMinutes: cfg.Windows.PollMinutes, Network: admin.Network, Logger: logger,
		}
		admin.Windows = svc
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		ws := &http.Server{
			Addr: cfg.Windows.Listen, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
			// 端末の証明書は求めるが、確かめるのは管理の道だけ（登録のときはまだ持っていない）。
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert, ClientCAs: pool},
		}
		servers = append(servers, ws)
		go func() {
			err := ws.ListenAndServeTLS(cfg.Windows.TLS.Cert, cfg.Windows.TLS.Key)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
	}

	if cfg.AppleEnabled() {
		ca, err := pki.LoadOrCreateCA(cfg.Apple.CACert, cfg.Apple.CAKey, "mdm Apple device CA")
		if err != nil {
			return fmt.Errorf("apple の認証局: %w", err)
		}
		svc := &apple.Service{
			Store: store, Engine: engine, Clock: clock, CA: ca,
			BaseURL: cfg.Apple.BaseURL, DoHBaseURL: admin.Endpoints.DoHBaseURL, Network: admin.Network, Logger: logger,
		}
		if cfg.Apple.PushCert != "" {
			pushCert, err := tls.LoadX509KeyPair(cfg.Apple.PushCert, cfg.Apple.PushKey)
			if err != nil {
				return fmt.Errorf("apple.push_cert: %w", err)
			}
			apns, err := apple.NewAPNs(pushCert)
			if err != nil {
				return err
			}
			svc.Pusher, svc.Topic = apns, apns.Topic
		}
		if cfg.Apple.VendorCert != "" {
			vendor, err := tls.LoadX509KeyPair(cfg.Apple.VendorCert, cfg.Apple.VendorKey)
			if err != nil {
				return fmt.Errorf("apple.vendor_cert: %w", err)
			}
			chain, err := os.ReadFile(cfg.Apple.VendorCert)
			if err != nil {
				return err
			}
			signer, ok := vendor.PrivateKey.(crypto.Signer)
			if !ok {
				return errors.New("apple.vendor_key: 署名に使えない鍵")
			}
			svc.Vendor = &apple.Vendor{ChainPEM: chain, Key: signer}
		}
		admin.Apple = svc
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		as := &http.Server{
			Addr: cfg.Apple.Listen, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
			// 端末の証明書は求めるが、確かめるのは管理の道だけ（プロファイルを取りに来るときはまだ持っていない）。
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert, ClientCAs: pool},
		}
		servers = append(servers, as)
		go func() {
			err := as.ListenAndServeTLS(cfg.Apple.TLS.Cert, cfg.Apple.TLS.Key)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errc <- err
		}()
		go svc.Run(ctx, cfg.Apple.SyncInterval)
	}

	go qlog.Run(ctx, 2*time.Second)
	go every(ctx, time.Hour, func() {
		n, err := store.DeleteQueryLogsBefore(ctx, clock.Now().AddDate(0, 0, -cfg.Filter.QueryLogRetentionDays))
		if err != nil {
			logger.Error("query log retention", "err", err)
		} else if n > 0 {
			logger.Info("query log retention", "deleted", n)
		}
		if _, err := store.DeleteFinishedCommandsBefore(ctx, clock.Now().AddDate(0, 0, -30)); err != nil {
			logger.Error("command retention", "err", err)
		}
		// 1 日送れなかった知らせは捨てる（iam は 24 時間より古い SET を受けない）。
		if n, err := store.DeleteSSFBefore(ctx, clock.Now().AddDate(0, 0, -1)); err != nil {
			logger.Error("ssf retention", "err", err)
		} else if n > 0 {
			logger.Warn("ssf: 送れなかった知らせを捨てた", "count", n)
		}
	})
	go func() {
		refresher.RefreshAll(ctx)
		every(ctx, cfg.Blocklists.RefreshInterval, func() { refresher.RefreshAll(ctx) })
	}()

	logger.Info("started", "admin", cfg.Admin.Listen, "public", cfg.Public.Listen, "dot", cfg.DoT.Listen, "windows", cfg.Windows.Listen, "apple", cfg.Apple.Listen, "radius", cfg.RADIUS.Listen)
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
