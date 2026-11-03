package config

import (
	"strings"
	"testing"
	"time"
)

const valid = `
public:
  base_url: https://dns.example.com/
admin:
  tokens:
    - name: parent
      sha256: 0000000000000000000000000000000000000000000000000000000000000000
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Public.BaseURL != "https://dns.example.com" || c.PublicHost() != "dns.example.com" || c.Upstream.DoH == "" || len(c.Filter.AlwaysAllow) == 0 {
		t.Fatalf("既定: %+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	for name, extra := range map[string]string{
		"知らない項目":   "\nunknown: 1\n",
		"DoT の証明書": "\ndot:\n  listen: \":853\"\n  domain: dns.example.com\n",
		"上流が 2 つ":  "\nupstream:\n  doh: https://1.1.1.1/dns-query\n  plain: 192.168.1.1:53\n",
		"短い間隔":     "\nblocklists:\n  refresh_interval: 1m\n",
	} {
		if _, err := Parse([]byte(valid + extra)); err == nil {
			t.Errorf("%s: エラーになるべき", name)
		}
	}
	_, err := Parse([]byte("public:\n  base_url: http://x\n"))
	if err == nil || !strings.Contains(err.Error(), "base_url") || !strings.Contains(err.Error(), "admin.tokens") {
		t.Errorf("まとめて出す: %v", err)
	}
}

func TestAdminListenNeedsTLSOffLoopback(t *testing.T) {
	base := strings.Replace(valid, "admin:\n", "admin:\n  listen: \"%s\"\n", 1)
	for addr, ok := range map[string]bool{"127.0.0.1:8091": true, "[::1]:8091": true, "localhost:8091": true, "0.0.0.0:8091": false, "192.168.1.10:8091": false} {
		_, err := Parse([]byte(strings.Replace(base, "%s", addr, 1)))
		if (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestOIDCAndTokenRoles(t *testing.T) {
	oidcOnly := "public:\n  base_url: https://dns.example.com\noidc:\n  issuer: https://iam.example.com\n  client_id: mdm\n  client_secret: x\n"
	if _, err := Parse([]byte(oidcOnly)); err != nil {
		t.Fatalf("oidc だけでも起動できる: %v", err)
	}
	for name, y := range map[string]string{
		"secret が無い":           "public:\n  base_url: https://dns.example.com\noidc:\n  issuer: https://iam.example.com\n  client_id: mdm\n",
		"http の issuer":        "public:\n  base_url: https://dns.example.com\noidc:\n  issuer: http://iam.example.com\n  client_id: mdm\n  client_secret: x\n",
		"org_id の無い org_admin": strings.Replace(valid, "      sha256:", "      role: org_admin\n      sha256:", 1),
		"知らない役割":               strings.Replace(valid, "      sha256:", "      role: god\n      sha256:", 1),
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: エラーになるべき", name)
		}
	}
}

func TestAndroid(t *testing.T) {
	c, err := Parse([]byte(valid + "android:\n  project_id: p\n  credentials_file: /k.json\n"))
	if err != nil || !c.AndroidEnabled() || c.Android.SyncInterval != 5*time.Minute {
		t.Fatal(c, err)
	}
	if c, _ := Parse([]byte(valid)); c.AndroidEnabled() {
		t.Fatal("android enabled without config")
	}
	for _, y := range []string{
		"android:\n  project_id: p\n",
		"android:\n  credentials_file: /k.json\n",
		"android:\n  project_id: p\n  credentials_file: /k.json\n  sync_interval: 10s\n",
	} {
		if _, err := Parse([]byte(valid + y)); err == nil {
			t.Errorf("%q: no error", y)
		}
	}
}

func TestWindows(t *testing.T) {
	ok := valid + "windows:\n  listen: \":8443\"\n  base_url: https://mdm.example.com:8443/\n  tls:\n    cert: c.pem\n    key: k.pem\n"
	c, err := Parse([]byte(ok))
	if err != nil || !c.WindowsEnabled() || c.Windows.BaseURL != "https://mdm.example.com:8443" || c.Windows.PollMinutes != 15 || c.Windows.CACert == "" {
		t.Fatal(c, err)
	}
	for _, y := range []string{
		"windows:\n  listen: \":8443\"\n  base_url: https://mdm.example.com\n",                                                  // tls が無い
		"windows:\n  listen: \":8443\"\n  base_url: http://mdm.example.com\n  tls:\n    cert: c\n    key: k\n",                  // http
		"windows:\n  listen: \":8443\"\n  base_url: https://m.example\n  tls:\n    cert: c\n    key: k\n  poll_minutes: 5000\n", // 長すぎる
	} {
		if _, err := Parse([]byte(valid + y)); err == nil {
			t.Errorf("%q: no error", y)
		}
	}
}

func TestApple(t *testing.T) {
	base := "apple:\n  listen: \":9443\"\n  base_url: https://mdm.example.com:9443/\n  tls:\n    cert: c.pem\n    key: k.pem\n"
	c, err := Parse([]byte(valid + base + "  push_cert: p.pem\n  push_key: pk.pem\n"))
	if err != nil || !c.AppleEnabled() || c.Apple.BaseURL != "https://mdm.example.com:9443" || c.Apple.SyncInterval != time.Hour || c.Apple.CACert != "apple-ca.pem" {
		t.Fatal(c, err)
	}
	for _, y := range []string{
		base, // 通知用の証明書が無い
		"apple:\n  listen: \":9443\"\n  base_url: https://m.example\n  push_cert: p\n  push_key: k\n", // tls が無い
		base + "  push_cert: p\n  push_key: k\n  sync_interval: 10s\n",                                // 短すぎる
	} {
		if _, err := Parse([]byte(valid + y)); err == nil {
			t.Errorf("%q: no error", y)
		}
	}
}
