package config

import (
	"strings"
	"testing"
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
