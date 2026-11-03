// Package config は設定ファイル（YAML）を読む。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// Config は設定のすべて。
type Config struct {
	Storage struct {
		SQLite string `yaml:"sqlite"`
	} `yaml:"storage"`
	Admin struct {
		Listen string                `yaml:"listen"`
		Tokens []adminapi.AdminToken `yaml:"tokens"`
		// TLS は管理の API を家の中の別の機械から使うときに書く。鍵が平文で流れないようにする。
		TLS TLS `yaml:"tls"`
	} `yaml:"admin"`
	// OIDC は管理者が IAM でログインするための設定。書かなければ admin.tokens の鍵だけで使う。
	OIDC struct {
		Issuer       string `yaml:"issuer"`
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		// Audience は、トークンの aud にこれが含まれることを求める（空なら求めない）。
		Audience string `yaml:"audience"`
		// IntrospectionEndpoint が空なら issuer の Discovery から引く。
		IntrospectionEndpoint string `yaml:"introspection_endpoint"`
	} `yaml:"oidc"`
	Public struct {
		Listen  string `yaml:"listen"`
		BaseURL string `yaml:"base_url"`
		TLS     TLS    `yaml:"tls"`
	} `yaml:"public"`
	DoT struct {
		Listen string `yaml:"listen"`
		Domain string `yaml:"domain"`
		TLS    TLS    `yaml:"tls"`
	} `yaml:"dot"`
	Upstream struct {
		DoH   string `yaml:"doh"`
		Plain string `yaml:"plain"`
	} `yaml:"upstream"`
	Filter struct {
		AlwaysAllow           []string `yaml:"always_allow"`
		QueryLogRetentionDays int      `yaml:"query_log_retention_days"`
	} `yaml:"filter"`
	Blocklists struct {
		RefreshInterval time.Duration `yaml:"refresh_interval"`
	} `yaml:"blocklists"`
	// Android は Google の Android Management API で Android の端末を管理する設定。無ければ使わない。
	Android struct {
		// ProjectID は Android Management API を有効にした Google Cloud のプロジェクトの ID。
		ProjectID string `yaml:"project_id"`
		// CredentialsFile はそのプロジェクトのサービスアカウントの鍵（JSON）。
		CredentialsFile string `yaml:"credentials_file"`
		// SyncInterval ごとに端末の状態を取り込む。
		SyncInterval time.Duration `yaml:"sync_interval"`
	} `yaml:"android"`
	// Windows は Windows 標準の MDM で Windows の端末を管理する設定。無ければ使わない。
	// 端末は TLS のクライアント証明書で自分を示すので、前にリバースプロキシを置かず、この入り口で TLS を受ける。
	Windows struct {
		Listen string `yaml:"listen"`
		// BaseURL は端末から届く https://host[:port]（登録の画面の「サーバー」に入れる）。
		BaseURL string `yaml:"base_url"`
		TLS     TLS    `yaml:"tls"`
		// CACert と CAKey は端末の証明書を発行する認証局。無ければ最初の起動で作る。
		CACert string `yaml:"ca_cert"`
		CAKey  string `yaml:"ca_key"`
		// PollMinutes ごとに端末が通信してくる（命令が届くまでの時間）。
		PollMinutes int `yaml:"poll_minutes"`
	} `yaml:"windows"`
}

// WindowsEnabled は Windows の管理を使うか。
func (c *Config) WindowsEnabled() bool { return c.Windows.Listen != "" }

// AndroidEnabled は Android の管理を使うか。
func (c *Config) AndroidEnabled() bool { return c.Android.ProjectID != "" }

// TLS は証明書のファイル。空なら TLS を使わない（前に置いたリバースプロキシで終端する）。
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Enabled は TLS を使うか。
func (t TLS) Enabled() bool { return t.Cert != "" || t.Key != "" }

// DefaultAlwaysAllow は、止める時間帯や「許可の一覧だけ」でも止めない通信の既定。
// 端末の管理（プッシュ）と時刻合わせが止まると、設定を届けられなくなるため。
var DefaultAlwaysAllow = []string{
	"push.apple.com",                   // Apple のプッシュ（MDM の合図）
	"time.apple.com",                   // 時刻
	"mtalk.google.com",                 // Google のプッシュ（FCM）
	"androidmanagement.googleapis.com", // Android Management API
	"time.android.com",                 // 時刻
	"connectivitycheck.gstatic.com",    // Android のネットワークの確認（止めると「インターネットなし」になる）
	"notify.windows.com",               // Windows のプッシュ（WNS）
	"time.windows.com",                 // 時刻
}

// Load は path を読み、既定を補い、確かめる。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse は YAML を読む。
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Storage.SQLite == "" {
		c.Storage.SQLite = "mdm.db"
	}
	if c.Admin.Listen == "" {
		c.Admin.Listen = "127.0.0.1:8091"
	}
	if c.Public.Listen == "" {
		c.Public.Listen = ":8090"
	}
	if c.Upstream.DoH == "" && c.Upstream.Plain == "" {
		c.Upstream.DoH = "https://1.1.1.1/dns-query"
	}
	if c.Filter.AlwaysAllow == nil {
		c.Filter.AlwaysAllow = DefaultAlwaysAllow
	}
	if c.Filter.QueryLogRetentionDays == 0 {
		c.Filter.QueryLogRetentionDays = 30
	}
	if c.Blocklists.RefreshInterval == 0 {
		c.Blocklists.RefreshInterval = 24 * time.Hour
	}
	if c.Windows.CACert == "" {
		c.Windows.CACert = "windows-ca.pem"
	}
	if c.Windows.CAKey == "" {
		c.Windows.CAKey = "windows-ca-key.pem"
	}
	if c.Windows.PollMinutes == 0 {
		c.Windows.PollMinutes = 15
	}
	c.Windows.BaseURL = strings.TrimSuffix(c.Windows.BaseURL, "/")
	if c.Android.SyncInterval == 0 {
		c.Android.SyncInterval = 5 * time.Minute
	}
	c.Public.BaseURL = strings.TrimSuffix(c.Public.BaseURL, "/")
}

func (c *Config) validate() error {
	var errs []error
	u, err := url.Parse(c.Public.BaseURL)
	if c.Public.BaseURL == "" || err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("public.base_url は端末から届く https://host（DoH の URL に使う）"))
	}
	if len(c.Admin.Tokens) == 0 && c.OIDC.Issuer == "" {
		errs = append(errs, errors.New("admin.tokens か oidc が要る（鍵は mdm admin-token で作る）"))
	}
	for i, t := range c.Admin.Tokens {
		if t.Name == "" || len(t.SHA256) != 64 {
			errs = append(errs, fmt.Errorf("admin.tokens[%d] は name と sha256（64 桁の 16 進）が要る", i))
		}
		switch {
		case t.Role == "" || t.Role == core.AdminServer:
			if t.OrgID != "" {
				errs = append(errs, fmt.Errorf("admin.tokens[%d]: server_admin に org_id は付けない", i))
			}
		case t.Role.Valid():
			if t.OrgID == "" {
				errs = append(errs, fmt.Errorf("admin.tokens[%d]: %s には org_id が要る", i, t.Role))
			}
		default:
			errs = append(errs, fmt.Errorf("admin.tokens[%d]: role は server_admin・org_admin・org_viewer のどれか", i))
		}
	}
	if o := c.OIDC; o.Issuer != "" || o.ClientID != "" {
		if u, err := url.Parse(o.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("oidc.issuer は https の URL"))
		}
		if o.ClientID == "" || o.ClientSecret == "" {
			errs = append(errs, errors.New("oidc は client_id と client_secret が要る（イントロスペクションに使う）"))
		}
		if o.IntrospectionEndpoint != "" {
			if u, err := url.Parse(o.IntrospectionEndpoint); err != nil || u.Scheme != "https" {
				errs = append(errs, errors.New("oidc.introspection_endpoint は https の URL"))
			}
		}
	}
	if c.Upstream.DoH != "" && c.Upstream.Plain != "" {
		errs = append(errs, errors.New("upstream は doh か plain のどちらか"))
	}
	if c.Upstream.DoH != "" {
		if u, err := url.Parse(c.Upstream.DoH); err != nil || u.Scheme != "https" {
			errs = append(errs, errors.New("upstream.doh は https の URL"))
		}
	}
	if c.DoT.Listen != "" {
		if filter.Normalize(c.DoT.Domain) == "" {
			errs = append(errs, errors.New("dot.domain が要る（端末のホスト名は {秘密}.{domain}）"))
		}
		if c.DoT.TLS.Cert == "" || c.DoT.TLS.Key == "" {
			errs = append(errs, errors.New("dot.tls の cert と key が要る（*.{domain} の証明書）"))
		}
	}
	if c.Admin.TLS.Enabled() && (c.Admin.TLS.Cert == "" || c.Admin.TLS.Key == "") {
		errs = append(errs, errors.New("admin.tls は cert と key の両方"))
	}
	if !c.Admin.TLS.Enabled() && !isLoopback(c.Admin.Listen) {
		errs = append(errs, errors.New("admin.listen を 127.0.0.1・::1 以外にするなら admin.tls が要る（管理の鍵が平文で流れるため）"))
	}
	if c.Public.TLS.Enabled() && (c.Public.TLS.Cert == "" || c.Public.TLS.Key == "") {
		errs = append(errs, errors.New("public.tls は cert と key の両方"))
	}
	for _, d := range c.Filter.AlwaysAllow {
		if filter.Normalize(d) == "" {
			errs = append(errs, fmt.Errorf("filter.always_allow に使えないドメイン %q", d))
		}
	}
	if c.Filter.QueryLogRetentionDays < 1 {
		errs = append(errs, errors.New("filter.query_log_retention_days は 1 以上"))
	}
	if a := c.Android; a.ProjectID != "" || a.CredentialsFile != "" {
		if a.ProjectID == "" || a.CredentialsFile == "" {
			errs = append(errs, errors.New("android は project_id と credentials_file の両方が要る"))
		}
		if a.SyncInterval < time.Minute {
			errs = append(errs, errors.New("android.sync_interval は 1m 以上"))
		}
	}
	if wc := c.Windows; wc.Listen != "" {
		if u, err := url.Parse(wc.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
			errs = append(errs, errors.New("windows.base_url は端末から届く https://host[:port]"))
		}
		if wc.TLS.Cert == "" || wc.TLS.Key == "" {
			errs = append(errs, errors.New("windows.tls の cert と key が要る（端末の証明書を受け取るため、ここで TLS を受ける）"))
		}
		if wc.PollMinutes < 1 || wc.PollMinutes > 1440 {
			errs = append(errs, errors.New("windows.poll_minutes は 1〜1440"))
		}
	}
	if c.Blocklists.RefreshInterval < time.Hour {
		errs = append(errs, errors.New("blocklists.refresh_interval は 1h 以上"))
	}
	return errors.Join(errs...)
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PublicHost は base_url のホスト名。いつも許す通信に足す（端末がフィルターの設定を取りに来られるように）。
func (c *Config) PublicHost() string {
	u, _ := url.Parse(c.Public.BaseURL)
	return u.Hostname()
}
