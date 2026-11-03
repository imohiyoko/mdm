// Package config は設定ファイル（YAML）を読む。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
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
		// BaseURL は管理の入り口の https://host[:port]（ブラウザーから届くもの）。oidc と一緒に書くと管理画面（/ui/）を使える。
		// IAM の連携先の戻り先に {base_url}/ui/callback を登録する。
		BaseURL string `yaml:"base_url"`
		// TLS は管理の API を家の中の別の機械から使うときに書く。鍵が平文で流れないようにする。
		TLS TLS `yaml:"tls"`
	} `yaml:"admin"`
	// RulesAPI はルールの API（ADR 0016）。AI・自動化・IaC からポリシーのルールを読み書きする口。
	RulesAPI struct {
		// Listen が空なら使わない。
		Listen string `yaml:"listen"`
		// TLS は 127.0.0.1・::1 以外で待ち受けるときに要る。
		TLS TLS `yaml:"tls"`
	} `yaml:"rules_api"`
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
	// Limits は組織ごとの上限の既定（0 か書かなければ上限なし）。組織ごとの値はサーバーの管理者が API で決める。
	Limits struct {
		Devices  int `yaml:"devices"`
		People   int `yaml:"people"`
		Groups   int `yaml:"groups"`
		Policies int `yaml:"policies"`
	} `yaml:"limits"`
	// Signup は IAM でログインした人が自分で組織を作れるようにする（oidc が要る）。
	Signup struct {
		Enabled bool `yaml:"enabled"`
		// MaxOrgsPerUser は 1 人が自分で作れる組織の数（0 なら 3）。
		MaxOrgsPerUser int `yaml:"max_orgs_per_user"`
	} `yaml:"signup"`
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
	// Apple は Apple 標準の MDM で iPhone・iPad・Mac を管理する設定。無ければ使わない。
	// 端末は TLS のクライアント証明書で自分を示すので、Windows と同じく、この入り口で TLS を受ける。
	Apple struct {
		Listen string `yaml:"listen"`
		// BaseURL は端末から届く https://host[:port]。
		BaseURL string `yaml:"base_url"`
		TLS     TLS    `yaml:"tls"`
		// PushCert と PushKey は MDM の通知用の証明書（Apple Push Certificates Portal で取ったもの）と鍵（PEM）。
		// 組織が自分の証明書を入れていないときに使う。書かなければ、組織ごとに入れる。
		PushCert string `yaml:"push_cert"`
		PushKey  string `yaml:"push_key"`
		// VendorCert と VendorKey は MDM の提供者の証明書（Apple Developer の MDM CSR）と鍵。VendorCert には
		// Apple の中間証明書とルート証明書もつなげる。あれば、組織の通知用の証明書の要求（CSR）に署名する。
		VendorCert string `yaml:"vendor_cert"`
		VendorKey  string `yaml:"vendor_key"`
		// CACert と CAKey は端末の証明書を発行する認証局。無ければ最初の起動で作る。
		CACert string `yaml:"ca_cert"`
		CAKey  string `yaml:"ca_key"`
		// SyncInterval ごとにポリシーの変更を確かめ、端末の情報を取りに行く。
		SyncInterval time.Duration `yaml:"sync_interval"`
	} `yaml:"apple"`
	// RADIUS は Wi-Fi のアクセスポイント（ルーター）からの認証を受ける。端末は MDM が発行した証明書で入る（EAP-TLS）。
	RADIUS struct {
		// Listen は UDP の待ち受け（例 ":1812"）。空なら使わない。
		Listen string `yaml:"listen"`
		// ServerName はサーバーの証明書の名前（例 radius.home.example）。端末の Wi-Fi の設定の「サーバーの名前」に入れる。
		// 実際に DNS で引ける名前でなくてよい。
		ServerName string `yaml:"server_name"`
		// CACert と CAKey はネットワークの認証局。無ければ最初の起動で作る。
		CACert string `yaml:"ca_cert"`
		CAKey  string `yaml:"ca_key"`
		// RequireCompliant なら、準拠している端末だけを入れる。
		RequireCompliant bool           `yaml:"require_compliant"`
		Clients          []RADIUSClient `yaml:"clients"`
		// RadSecListen は RadSec（RADIUS over TLS、TCP）の待ち受け（例 ":2083"）。空なら使わない。
		// 組織の管理者は、アドレスの代わりに証明書で見分けるルーターを登録できる。
		RadSecListen string `yaml:"radsec_listen"`
		// RadSecAddress はルーターに設定させる入り口（host:port）。空なら server_name と radsec_listen のポート。
		RadSecAddress string `yaml:"radsec_address"`
		// RadSecCACert と RadSecCAKey はルーターの証明書を発行する認証局。無ければ最初の起動で作る。
		RadSecCACert string `yaml:"radsec_ca_cert"`
		RadSecCAKey  string `yaml:"radsec_ca_key"`
	} `yaml:"radius"`
	// Compliance は端末の準拠の判定。
	Compliance struct {
		// Interval ごとにすべての端末を判定し、送れなかった知らせを送り直す。
		Interval time.Duration `yaml:"interval"`
	} `yaml:"compliance"`
	// SSF は準拠の状態の変化を IAM などに知らせる（OpenID Shared Signals Framework、CAEP の device-compliance-change）。
	// SET の iss は public.base_url。受け手は public.base_url の /.well-known/jwks.json で署名を確かめる。
	SSF struct {
		// SigningKey は SET に署名する鍵（P-256、PEM）。無ければ最初の起動で作る。
		SigningKey string        `yaml:"signing_key"`
		Receivers  []SSFReceiver `yaml:"receivers"`
	} `yaml:"ssf"`
}

// RADIUSClient は RADIUS で問い合わせてくるアクセスポイント（ルーター）。
type RADIUSClient struct {
	Name string `yaml:"name"`
	// Address は IP アドレスか CIDR（例 192.168.1.1、192.168.1.0/24）。
	Address string `yaml:"address"`
	// SecretFile は共有の秘密を入れたファイル（16 文字以上。アクセスポイントにも同じものを入れる）。
	SecretFile string `yaml:"secret_file"`
	// OrgIDs があれば、その組織の端末だけを入れる。空ならどの組織の端末も入れる。
	OrgIDs OrgIDList `yaml:"org_ids"`
}

// RADIUSEnabled は Wi-Fi の認証を使うか。
func (c *Config) RADIUSEnabled() bool { return c.RADIUS.Listen != "" }

// SSFReceiver は SET を送る受け手。
type SSFReceiver struct {
	Name string `yaml:"name"`
	// URL は受け口（iam なら https://iam.example/ssf/receiver/{送信側の ID}）。
	URL string `yaml:"url"`
	// PushTokenFile は受け手が出した Bearer の値（iam なら登録のときに 1 度だけ返る ssfpt_…）を入れたファイル。
	PushTokenFile string `yaml:"push_token_file"`
	// Audience は SET の aud（受け手に登録した audience）。
	Audience string `yaml:"audience"`
	// OrgIDs があれば、その組織の端末の知らせだけを送る。空ならすべての組織の知らせを送る。
	OrgIDs OrgIDList `yaml:"org_ids"`
}

// AppleEnabled は iPhone・iPad・Mac の管理を使うか。
func (c *Config) AppleEnabled() bool { return c.Apple.Listen != "" }

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
	if c.Apple.CACert == "" {
		c.Apple.CACert = "apple-ca.pem"
	}
	if c.Apple.CAKey == "" {
		c.Apple.CAKey = "apple-ca-key.pem"
	}
	if c.Apple.SyncInterval == 0 {
		c.Apple.SyncInterval = time.Hour
	}
	c.Apple.BaseURL = strings.TrimSuffix(c.Apple.BaseURL, "/")
	if c.RADIUS.CACert == "" {
		c.RADIUS.CACert = "network-ca.pem"
	}
	if c.RADIUS.CAKey == "" {
		c.RADIUS.CAKey = "network-ca-key.pem"
	}
	if c.RADIUS.RadSecCACert == "" {
		c.RADIUS.RadSecCACert = "radsec-ca.pem"
	}
	if c.RADIUS.RadSecCAKey == "" {
		c.RADIUS.RadSecCAKey = "radsec-ca-key.pem"
	}
	if c.RADIUS.RadSecListen != "" && c.RADIUS.RadSecAddress == "" {
		if _, port, err := net.SplitHostPort(c.RADIUS.RadSecListen); err == nil {
			c.RADIUS.RadSecAddress = net.JoinHostPort(c.RADIUS.ServerName, port)
		}
	}
	if c.Compliance.Interval == 0 {
		c.Compliance.Interval = time.Minute
	}
	if c.SSF.SigningKey == "" {
		c.SSF.SigningKey = "ssf-key.pem"
	}
	if c.Android.SyncInterval == 0 {
		c.Android.SyncInterval = 5 * time.Minute
	}
	c.Public.BaseURL = strings.TrimSuffix(c.Public.BaseURL, "/")
	c.Admin.BaseURL = strings.TrimSuffix(c.Admin.BaseURL, "/")
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
	if c.Admin.BaseURL != "" {
		if u, err := url.Parse(c.Admin.BaseURL); err != nil || u.Host == "" || u.Path != "" && u.Path != "/" ||
			u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Host)) {
			errs = append(errs, errors.New("admin.base_url は https://host[:port]（手元の http://127.0.0.1:port も可）"))
		}
		if c.OIDC.Issuer == "" {
			errs = append(errs, errors.New("admin.base_url（管理画面）は oidc が要る（IAM でログインする）"))
		}
	}
	if c.Signup.Enabled && c.OIDC.Issuer == "" {
		errs = append(errs, errors.New("signup は oidc が要る（IAM でログインした人が組織を作る）"))
	}
	if l := c.Limits; l.Devices < 0 || l.People < 0 || l.Groups < 0 || l.Policies < 0 {
		errs = append(errs, errors.New("limits は 0 以上（0 は上限なし）"))
	}
	if c.Signup.MaxOrgsPerUser < 0 {
		errs = append(errs, errors.New("signup.max_orgs_per_user は 0 以上"))
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
	if ra := c.RulesAPI; ra.Listen != "" {
		if _, _, err := net.SplitHostPort(ra.Listen); err != nil {
			errs = append(errs, errors.New("rules_api.listen は host:port"))
		}
		if ra.TLS.Enabled() && (ra.TLS.Cert == "" || ra.TLS.Key == "") {
			errs = append(errs, errors.New("rules_api.tls は cert と key の両方"))
		}
		if !ra.TLS.Enabled() && !isLoopback(ra.Listen) {
			errs = append(errs, errors.New("rules_api.listen を 127.0.0.1・::1 以外にするなら rules_api.tls が要る（トークンが平文で流れるため）"))
		}
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
		if !isOrigin(wc.BaseURL) {
			errs = append(errs, errors.New("windows.base_url は端末から届く https://host[:port]"))
		}
		if wc.TLS.Cert == "" || wc.TLS.Key == "" {
			errs = append(errs, errors.New("windows.tls の cert と key が要る（端末の証明書を受け取るため、ここで TLS を受ける）"))
		}
		if wc.PollMinutes < 1 || wc.PollMinutes > 1440 {
			errs = append(errs, errors.New("windows.poll_minutes は 1〜1440"))
		}
	}
	if ac := c.Apple; ac.Listen != "" {
		if !isOrigin(ac.BaseURL) {
			errs = append(errs, errors.New("apple.base_url は端末から届く https://host[:port]"))
		}
		if ac.TLS.Cert == "" || ac.TLS.Key == "" {
			errs = append(errs, errors.New("apple.tls の cert と key が要る（端末の証明書を受け取るため、ここで TLS を受ける）"))
		}
		if (ac.PushCert == "") != (ac.PushKey == "") {
			errs = append(errs, errors.New("apple.push_cert と push_key は両方書く（Apple Push Certificates Portal で取る MDM の通知用の証明書）"))
		}
		if (ac.VendorCert == "") != (ac.VendorKey == "") {
			errs = append(errs, errors.New("apple.vendor_cert と vendor_key は両方書く"))
		}
		if ac.SyncInterval < time.Minute {
			errs = append(errs, errors.New("apple.sync_interval は 1m 以上"))
		}
	}
	if rc := c.RADIUS; rc.RadSecListen != "" {
		if rc.Listen == "" {
			errs = append(errs, errors.New("radius.radsec_listen は radius.listen と一緒に使う"))
		}
		if _, _, err := net.SplitHostPort(rc.RadSecListen); err != nil {
			errs = append(errs, errors.New("radius.radsec_listen は host:port（例 \":2083\"）"))
		}
		if h, _, err := net.SplitHostPort(rc.RadSecAddress); err != nil || h == "" {
			errs = append(errs, errors.New("radius.radsec_address は host:port"))
		}
	}
	if rc := c.RADIUS; rc.Listen != "" {
		if filter.Normalize(rc.ServerName) == "" || strings.Contains(rc.ServerName, "*") {
			errs = append(errs, errors.New("radius.server_name が要る（例 radius.home.example）"))
		}
		if len(rc.Clients) == 0 && rc.RadSecListen == "" {
			// RadSec を使うなら、ルーターは組織の管理者が登録するだけでもよい。
			errs = append(errs, errors.New("radius.clients が要る（問い合わせてくるルーター）"))
		}
		seen := map[string]bool{}
		prefixes := map[netip.Prefix]bool{}
		for i, cl := range rc.Clients {
			if p, err := ParseClientAddress(cl.Address); err == nil {
				if prefixes[p] {
					errs = append(errs, fmt.Errorf("radius.clients[%d]: address %s がほかと同じ", i, p))
				}
				prefixes[p] = true
			}
			if _, err := ParseClientAddress(cl.Address); err != nil || cl.Name == "" || cl.SecretFile == "" {
				errs = append(errs, fmt.Errorf("radius.clients[%d] は name・address（IP か CIDR）・secret_file が要る", i))
			}
			if strings.HasPrefix(cl.Name, "org:") {
				errs = append(errs, fmt.Errorf("radius.clients[%d]: name は org: で始めない（組織の管理者が登録したルーターの名前に使う）", i))
			}
			if seen[cl.Name] {
				errs = append(errs, fmt.Errorf("radius.clients[%d]: name %q がほかと重なっている", i, cl.Name))
			}
			seen[cl.Name] = true
			if slices.Contains(cl.OrgIDs, "") {
				errs = append(errs, fmt.Errorf("radius.clients[%d]: org_ids に空の値がある", i))
			}
		}
	}
	if c.Compliance.Interval < 10*time.Second {
		errs = append(errs, errors.New("compliance.interval は 10s 以上"))
	}
	names := map[string]bool{}
	for i, r := range c.SSF.Receivers {
		if r.Name == "" || names[r.Name] {
			errs = append(errs, fmt.Errorf("ssf.receivers[%d]: name は空でなく、ほかと違う名前", i))
		}
		names[r.Name] = true
		if u, err := url.Parse(r.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			errs = append(errs, fmt.Errorf("ssf.receivers[%d]: url は https の URL", i))
		}
		if r.PushTokenFile == "" || r.Audience == "" {
			errs = append(errs, fmt.Errorf("ssf.receivers[%d]: push_token_file と audience が要る", i))
		}
		if slices.Contains(r.OrgIDs, "") {
			errs = append(errs, fmt.Errorf("ssf.receivers[%d]: org_ids に空の値がある", i))
		}
	}
	if c.Blocklists.RefreshInterval < time.Hour {
		errs = append(errs, errors.New("blocklists.refresh_interval は 1h 以上"))
	}
	return errors.Join(errs...)
}

// isOrigin は https://host[:port] だけの URL か（パス・クエリ・フラグメント・利用者の情報が無い）。
func isOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery &&
		u.Fragment == "" && u.User == nil && u.Opaque == ""
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

// AllowHosts は通信フィルターでいつも通すこのサーバーのホスト名。端末がフィルターの設定を取りに来たり、
// 管理の通信（Windows・Apple）をしたりできるように、止める時間帯や「許可の一覧だけ」でも通す。
func (c *Config) AllowHosts() []string {
	hosts := []string{c.PublicHost()}
	for _, raw := range []string{c.Windows.BaseURL, c.Apple.BaseURL} {
		if u, err := url.Parse(raw); raw != "" && err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	return hosts
}

// ParseClientAddress は RADIUS のクライアントのアドレス（IP か CIDR）を読む。
func ParseClientAddress(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// OrgIDList は組織の ID の一覧。null や空の要素は誤りにする（読み落として制限が外れないように）。
type OrgIDList []string

// UnmarshalYAML は文字列の一覧だけを受ける。
func (l *OrgIDList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: org_ids は文字列の一覧", n.Line)
	}
	out := OrgIDList{}
	for _, e := range n.Content {
		if e.Kind != yaml.ScalarNode || e.Tag != "!!str" && e.Tag != "" || e.Value == "" {
			return fmt.Errorf("line %d: org_ids の要素は空でない文字列", e.Line)
		}
		out = append(out, e.Value)
	}
	*l = out
	return nil
}
