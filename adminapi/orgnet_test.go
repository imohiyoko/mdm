package adminapi_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/network"
	"github.com/imohiyoko/mdm/pki"
	"github.com/imohiyoko/mdm/ssf"
)

func TestOrgRADIUSClients(t *testing.T) {
	ca, err := pki.NewNetworkCA("net", "radius.example")
	if err != nil {
		t.Fatal(err)
	}
	var changed atomic.Int32
	c, store, _ := newServer(t, func(s *adminapi.Server) {
		s.Network = &network.Service{Store: s.Store, Clock: s.Clock, CA: ca, ServerName: "radius.example"}
		s.StaticRADIUSPrefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		s.RADIUSChanged = func() { changed.Add(1) }
	})
	admin := c.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID + "/radius-clients"
	var out map[string]any
	if code := admin.do("POST", base, map[string]any{"name": "本社", "address": "203.0.113.10"}, &out); code != 201 ||
		out["address"] != "203.0.113.10/32" || len(out["secret"].(string)) < 30 || out["server_name"] != "radius.example" {
		t.Fatal(code, out)
	}
	id := out["id"].(string)
	if changed.Load() != 1 {
		t.Fatal("no refresh")
	}
	for _, tc := range []struct {
		addr string
		code int
	}{
		{"192.168.1.1", 400},    // 家の中のアドレス
		{"203.0.113.0/16", 400}, // 広すぎる
		{"nope", 400},           //
		{"203.0.113.0/28", 409}, // 登録と重なる
		{"198.51.100.7", 409},   // 設定と重なる
		{"2001:db8::1", 400},    // 文書用
	} {
		if code := admin.do("POST", base, map[string]any{"name": "x", "address": tc.addr}, nil); code != tc.code {
			t.Errorf("%s: %d", tc.addr, code)
		}
	}
	// 見るだけの管理者は登録できない。一覧に秘密は出さない。
	if code := c.as("mdm_org_viewer").do("POST", base, map[string]any{"name": "x", "address": "203.0.113.200"}, nil); code != 403 {
		t.Fatal(code)
	}
	var list struct {
		RADIUSClients []map[string]any `json:"radius_clients"`
	}
	if c.as("mdm_org_viewer").do("GET", base, nil, &list); len(list.RADIUSClients) != 1 || list.RADIUSClients[0]["secret"] != nil {
		t.Fatal(list)
	}
	cs, _ := store.ListRADIUSClients(t.Context(), "")
	if len(cs) != 1 || cs[0].OrgID != testkit.OrgID {
		t.Fatal(cs)
	}
	if code := admin.do("DELETE", base+"/"+id, nil, nil); code != 204 || changed.Load() != 2 {
		t.Fatal(code)
	}
	if code := admin.do("DELETE", base+"/"+id, nil, nil); code != 404 {
		t.Fatal(code)
	}
}

func TestOrgRADIUSClientsOtherOrg(t *testing.T) {
	ca, _ := pki.NewNetworkCA("net", "radius.example")
	c, _, _ := newServer(t, func(s *adminapi.Server) {
		s.Network = &network.Service{Store: s.Store, Clock: s.Clock, CA: ca, ServerName: "radius.example"}
	})
	var org map[string]any
	c.do("POST", "/v1/orgs", map[string]any{"name": "別の会社", "kind": "company"}, &org)
	// 組織の管理者はほかの組織のルーターを見ることも登録することもできない。
	if code := c.as("mdm_org_admin").do("POST", "/v1/orgs/"+org["id"].(string)+"/radius-clients", map[string]any{"name": "x", "address": "203.0.113.10"}, nil); code != 404 {
		t.Fatal(code)
	}
}

func TestOrgSSFReceivers(t *testing.T) {
	signer, err := ssf.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := newServer(t, func(s *adminapi.Server) {
		tr := &ssf.Transmitter{Store: s.Store, Clock: s.Clock, Signer: signer, Issuer: "https://mdm.example",
			Dynamic: func(context.Context) ([]ssf.Receiver, error) { return nil, nil }}
		s.Compliance = &compliance.Service{Store: s.Store, Engine: s.Engine, Clock: s.Clock, Transmitter: tr}
	})
	admin := c.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID + "/ssf-receivers"
	in := map[string]any{"name": "社の IAM", "url": "https://iam.corp.example/ssf/receiver/stx_1", "push_token": "ssfpt_0123456789abcdef", "audience": "https://mdm.example"}
	var out map[string]any
	if code := admin.do("POST", base, in, &out); code != 201 || out["push_token"] != nil {
		t.Fatal(code, out)
	}
	for _, u := range []string{"http://iam.example/x", "https://127.0.0.1/x", "https://10.0.0.5/x", "https://[::1]/x", "https://localhost/x", "https://u:p@iam.example/x"} {
		bad := map[string]any{"name": "x", "url": u, "push_token": "ssfpt_0123456789abcdef", "audience": "a"}
		if code := admin.do("POST", base, bad, nil); code != 400 {
			t.Errorf("%s: %d", u, code)
		}
	}
	var list map[string]any
	if code := c.as("mdm_org_viewer").do("GET", base, nil, &list); code != 200 || list["jwks_uri"] != "https://mdm.example/.well-known/jwks.json" {
		t.Fatal(code, list)
	}
	rs := list["ssf_receivers"].([]any)
	if len(rs) != 1 || rs[0].(map[string]any)["push_token"] != nil {
		t.Fatal(rs)
	}
	if code := admin.do("DELETE", base+"/"+out["id"].(string), nil, nil); code != 204 {
		t.Fatal(code)
	}
}
