package adminapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
)

const secret = "mdm_test-secret"

type client struct {
	t     *testing.T
	srv   *httptest.Server
	token string
}

func (c client) as(token string) client { c.token = token; return c }

func (c client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, &buf)
	tok := c.token
	if tok == "" {
		tok = secret
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func newServer(t *testing.T, opts ...func(*adminapi.Server)) (client, core.Store, *testkit.Clock) {
	t.Helper()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	if err := store.CreatePolicy(context.Background(), core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	engine := &filter.Engine{Store: store, Clock: clock}
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	s := &adminapi.Server{
		Store: store, Clock: clock, Engine: engine,
		Refresher: &blocklist.Refresher{Store: store, Clock: clock, OnChange: engine.Invalidate},
		Tokens: []adminapi.AdminToken{
			{Name: "parent", SHA256: hash(secret)},
			{Name: "org-admin", SHA256: hash("mdm_org_admin"), Role: core.AdminOrg, OrgID: testkit.OrgID},
			{Name: "org-viewer", SHA256: hash("mdm_org_viewer"), Role: core.AdminOrgViewer, OrgID: testkit.OrgID},
		},
		Introspector: fakeIntrospector{"iam-token": {Active: true, Issuer: "https://iam.example", Subject: "user-1", Username: "boss@example.com"}},
		Issuer:       "https://iam.example",
		Endpoints:    adminapi.FilterEndpoints{DoHBaseURL: "https://dns.example", DoTDomain: "dns.example"},
	}
	for _, o := range opts {
		o(s)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return client{t: t, srv: srv}, store, clock
}

type fakeIntrospector map[string]adminapi.Introspection

func (f fakeIntrospector) Introspect(_ context.Context, token string) (adminapi.Introspection, error) {
	return f[token], nil
}

func TestAuth(t *testing.T) {
	c, _, _ := newServer(t)
	for _, h := range []string{"", "Bearer wrong", "Basic " + secret} {
		req, _ := http.NewRequest("GET", c.srv.URL+"/v1/devices", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%q: %d", h, resp.StatusCode)
		}
	}
	resp, _ := http.Get(c.srv.URL + "/healthz")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz: %d", resp.StatusCode)
	}
}

func TestFamilyFlow(t *testing.T) {
	c, store, clock := newServer(t)

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{
		"org_id": testkit.OrgID, "name": "小学生", "block": []string{"*.game.example"}, "allow": []string{"school.example"},
		"quiet_hours": []map[string]any{{"start": "21:00", "end": "07:00"}}, "time_zone": "Asia/Tokyo",
	}, &pol); code != 201 {
		t.Fatalf("policy: %d %v", code, pol)
	}
	polID := pol["id"].(string)
	if pol["block"].([]any)[0] != "game.example" || pol["mode"] != "blocklist" {
		t.Fatalf("正規化: %v", pol)
	}

	var person map[string]any
	if code := c.do("POST", "/v1/people", map[string]any{"name": "たろう"}, nil); code != 400 {
		t.Fatalf("サーバー全体の管理者は org_id を省けない: %d", code)
	}
	if code := c.do("POST", "/v1/people", map[string]any{"org_id": testkit.OrgID, "name": "たろう", "policy_id": polID}, &person); code != 201 {
		t.Fatalf("person: %d %v", code, person)
	}
	if person["role"] != "child" {
		t.Fatalf("既定は子ども: %v", person)
	}

	var created struct {
		Device map[string]any
		Filter map[string]string
	}
	if code := c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "たろうの Android", "platform": "android", "person_id": person["id"]}, &created); code != 201 {
		t.Fatalf("device: %d", code)
	}
	tok := created.Filter["token"]
	if !core.LooksLikeFilterToken(tok) || created.Filter["doh_url"] != "https://dns.example/dns-query/"+tok ||
		!strings.HasSuffix(created.Filter["dot_hostname"], ".dns.example") || strings.HasPrefix(created.Filter["dot_hostname"], tok) || !strings.HasSuffix(created.Filter["apple_profile_url"], tok+".mobileconfig") {
		t.Fatalf("filter setup: %v", created.Filter)
	}
	devID := created.Device["id"].(string)

	check := func(name string) map[string]any {
		var out map[string]any
		if code := c.do("POST", "/v1/devices/"+devID+"/check", map[string]any{"name": name}, &out); code != 200 {
			t.Fatalf("check: %d", code)
		}
		return out
	}
	if r := check("www.game.example"); r["action"] != "block" || r["policy_id"] != polID {
		t.Fatalf("持ち主のポリシー: %v", r)
	}

	// 今すぐ止める・戻す。
	if code := c.do("POST", "/v1/devices/"+devID+"/pause", map[string]any{"minutes": 30}, nil); code != 200 {
		t.Fatalf("pause: %d", code)
	}
	if r := check("news.example"); r["reason"] != "paused" {
		t.Fatalf("止めた: %v", r)
	}
	c.do("DELETE", "/v1/devices/"+devID+"/pause", nil, nil)
	if r := check("news.example"); r["action"] != "allow" {
		t.Fatalf("戻した: %v", r)
	}

	// 夜（22:00 JST）。
	clock.Set(time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC))
	if r := check("news.example"); r["reason"] != "quiet_hours" {
		t.Fatalf("夜: %v", r)
	}

	// 秘密の作り直し。古い秘密は効かない。
	var rotated struct{ Filter map[string]string }
	c.do("POST", "/v1/devices/"+devID+"/filter-token", nil, &rotated)
	if rotated.Filter["token"] == tok || !core.LooksLikeFilterToken(rotated.Filter["token"]) {
		t.Fatal("作り直し")
	}
	if _, err := store.GetDeviceByTokenHash(context.Background(), core.HashFilterToken(tok)); err != core.ErrNotFound {
		t.Fatal("古い秘密が残っている")
	}

	// 使われているものは消せない。既定のポリシーも消せない。
	if code := c.do("DELETE", "/v1/policies/"+polID, nil, nil); code != 409 {
		t.Fatalf("使用中のポリシー: %d", code)
	}
	if code := c.do("DELETE", "/v1/policies/default", nil, nil); code != 409 {
		t.Fatalf("既定のポリシー: %d", code)
	}
	if code := c.do("DELETE", "/v1/people/"+person["id"].(string), nil, nil); code != 409 {
		t.Fatalf("端末のある人: %d", code)
	}

	var audit struct{ Events []map[string]any }
	c.do("GET", "/v1/audit", nil, &audit)
	if len(audit.Events) < 6 || audit.Events[0]["actor"] != "parent" {
		t.Fatalf("操作の記録: %v", audit.Events)
	}
}

func TestValidation(t *testing.T) {
	c, _, _ := newServer(t)
	for _, body := range []map[string]any{
		{"name": "", "org_id": testkit.OrgID},
		{"name": "x", "mode": "everything"},
		{"name": "x", "block": []string{"not a domain"}},
		{"name": "x", "time_zone": "Mars/Base"},
		{"name": "x", "quiet_hours": []map[string]any{{"start": "25:00", "end": "07:00"}}},
		{"name": "x", "quiet_hours": []map[string]any{{"start": "07:00", "end": "07:00"}}},
		{"name": "x", "quiet_hours": []map[string]any{{"days": []string{"funday"}, "start": "07:00", "end": "08:00"}}},
		{"name": "x", "blocklists": []string{"bl_missing"}},
		{"name": "x", "unknown_field": true},
	} {
		if code := c.do("POST", "/v1/policies", body, nil); code != 400 {
			t.Errorf("%v: %d", body, code)
		}
	}
	if code := c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "x", "platform": "blackberry"}, nil); code != 400 {
		t.Errorf("platform: %d", code)
	}
	if code := c.do("POST", "/v1/blocklists", map[string]any{"name": "x", "url": "http://insecure.example/list"}, nil); code != 400 {
		t.Errorf("blocklist http: %d", code)
	}
	if code := c.do("GET", "/v1/devices/dev_missing", nil, nil); code != 404 {
		t.Errorf("missing device: %d", code)
	}
}

func TestOrgScoping(t *testing.T) {
	c, store, _ := newServer(t)
	ctx := context.Background()
	if err := store.CreateOrg(ctx, core.Org{ID: "org2", Name: "よその会社", Kind: core.OrgCompany}); err != nil {
		t.Fatal(err)
	}
	orgAdmin, viewer := c.as("mdm_org_admin"), c.as("mdm_org_viewer")

	// 組織の管理者は org_id を省ける（自分の組織になる）。
	var dev struct{ Device map[string]any }
	if code := orgAdmin.do("POST", "/v1/devices", map[string]any{"name": "会社の PC", "platform": "windows"}, &dev); code != 201 || dev.Device["org_id"] != testkit.OrgID {
		t.Fatalf("org admin create: %d %v", code, dev)
	}
	devID := dev.Device["id"].(string)
	// よその組織には作れない・見えない。
	if code := orgAdmin.do("POST", "/v1/devices", map[string]any{"org_id": "org2", "name": "x", "platform": "windows"}, nil); code != 404 {
		t.Fatalf("よその組織に作れた: %d", code)
	}
	var other struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": "org2", "name": "よその PC", "platform": "macos"}, &other)
	if code := orgAdmin.do("GET", "/v1/devices/"+other.Device["id"].(string), nil, nil); code != 404 {
		t.Fatalf("よその端末が見えた: %d", code)
	}
	var list struct{ Devices []map[string]any }
	orgAdmin.do("GET", "/v1/devices", nil, &list)
	if len(list.Devices) != 1 {
		t.Fatalf("一覧はその組織の分だけ: %v", list.Devices)
	}
	var orgs struct{ Orgs []map[string]any }
	orgAdmin.do("GET", "/v1/orgs", nil, &orgs)
	if len(orgs.Orgs) != 1 {
		t.Fatalf("組織の一覧: %v", orgs.Orgs)
	}

	// 見るだけの管理者は変えられない。
	if code := viewer.do("GET", "/v1/devices/"+devID, nil, nil); code != 200 {
		t.Fatalf("viewer get: %d", code)
	}
	if code := viewer.do("POST", "/v1/devices/"+devID+"/pause", map[string]any{"minutes": 5}, nil); code != 403 {
		t.Fatalf("viewer pause: %d", code)
	}

	// サーバー全体のもの（組織・一覧・サーバー全体のポリシー）は組織の管理者には変えられない。
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/orgs", map[string]any{"name": "x"}},
		{"POST", "/v1/blocklists", map[string]any{"name": "x", "url": "https://x.example/l"}},
		{"PUT", "/v1/policies/default", map[string]any{"name": "x"}},
		{"POST", "/v1/admins", map[string]any{"subject": "u", "role": "server_admin"}},
	} {
		if code := orgAdmin.do(req.method, req.path, req.body, nil); code != 403 {
			t.Errorf("%s %s: %d", req.method, req.path, code)
		}
	}

	// よその組織のポリシーやグループは指せない。
	var pol map[string]any
	c.do("POST", "/v1/policies", map[string]any{"org_id": "org2", "name": "よそ"}, &pol)
	if code := orgAdmin.do("PATCH", "/v1/devices/"+devID, map[string]any{"policy_id": pol["id"]}, nil); code != 400 {
		t.Fatalf("よそのポリシー: %d", code)
	}
}

func TestGroupPolicy(t *testing.T) {
	c, _, _ := newServer(t)
	a := c.as("mdm_org_admin")
	var low, high, g1, g2, person map[string]any
	a.do("POST", "/v1/policies", map[string]any{"name": "ゆるい", "block": []string{"a.example"}}, &low)
	a.do("POST", "/v1/policies", map[string]any{"name": "きびしい", "block": []string{"b.example"}}, &high)
	a.do("POST", "/v1/groups", map[string]any{"name": "全員", "policy_id": low["id"], "priority": 1}, &g1)
	a.do("POST", "/v1/groups", map[string]any{"name": "新人", "policy_id": high["id"], "priority": 10}, &g2)
	if code := a.do("POST", "/v1/people", map[string]any{"name": "さとう", "role": "adult", "group_ids": []any{g1["id"], g2["id"]}}, &person); code != 201 {
		t.Fatalf("person: %d %v", code, person)
	}
	var dev struct{ Device map[string]any }
	a.do("POST", "/v1/devices", map[string]any{"name": "PC", "platform": "windows", "person_id": person["id"]}, &dev)
	var got map[string]any
	a.do("GET", "/v1/devices/"+dev.Device["id"].(string), nil, &got)
	if got["effective_policy_id"] != high["id"] {
		t.Fatalf("優先度の高いグループのポリシー: %v", got)
	}
	// 人が入っているグループは消せない。
	if code := a.do("DELETE", "/v1/groups/"+g2["id"].(string), nil, nil); code != 409 {
		t.Fatalf("delete group in use: %d", code)
	}
	// 組織の既定のポリシー。
	var dev2 struct{ Device map[string]any }
	a.do("POST", "/v1/devices", map[string]any{"name": "共用", "platform": "android"}, &dev2)
	a.do("PATCH", "/v1/orgs/"+testkit.OrgID, map[string]any{"default_policy_id": low["id"]}, nil)
	a.do("GET", "/v1/devices/"+dev2.Device["id"].(string), nil, &got)
	if got["effective_policy_id"] != low["id"] {
		t.Fatalf("組織の既定: %v", got)
	}
	if code := a.do("DELETE", "/v1/policies/"+low["id"].(string), nil, nil); code != 409 {
		t.Fatalf("組織の既定のポリシーは消せない: %d", code)
	}
}

func TestIAMLogin(t *testing.T) {
	c, _, _ := newServer(t)
	iam := c.as("iam-token")
	// IAM でログインできても、管理者として登録されていなければ使えない（自分を見ることだけできる）。
	var none map[string]any
	if code := iam.do("GET", "/v1/me", nil, &none); code != 200 || len(none["roles"].([]any)) != 0 || none["can_signup"] != false {
		t.Fatalf("未登録の me: %d %v", code, none)
	}
	for _, path := range []string{"/v1/devices", "/v1/orgs", "/v1/policies", "/v1/me/"} {
		if code := iam.do("GET", path, nil, nil); code != 401 {
			t.Fatalf("未登録 %s: %d", path, code)
		}
	}
	if code := c.as("unknown").do("GET", "/v1/me", nil, nil); code != 401 {
		t.Fatalf("無効なトークン: %d", code)
	}
	// 組織の管理者は自分の組織の管理者を足せる（issuer は設定のもの）。
	var b map[string]any
	if code := c.as("mdm_org_admin").do("POST", "/v1/admins", map[string]any{"subject": "user-1", "role": "org_admin", "org_id": testkit.OrgID}, &b); code != 201 || b["issuer"] != "https://iam.example" {
		t.Fatalf("add admin: %d %v", code, b)
	}
	var me map[string]any
	if code := iam.do("GET", "/v1/me", nil, &me); code != 200 || me["name"] != "boss@example.com" {
		t.Fatalf("me: %d %v", code, me)
	}
	if code := iam.do("POST", "/v1/people", map[string]any{"name": "すずき", "role": "adult"}, nil); code != 201 {
		t.Fatalf("IAM の管理者で作る: %d", code)
	}
	var audit struct{ Events []map[string]any }
	c.do("GET", "/v1/audit", nil, &audit)
	if audit.Events[0]["actor"] != "boss@example.com" || audit.Events[0]["org_id"] != testkit.OrgID {
		t.Fatalf("操作の記録: %v", audit.Events[0])
	}
	if code := c.do("POST", "/v1/admins", map[string]any{"subject": "user-1", "role": "org_admin", "org_id": testkit.OrgID}, nil); code != 409 {
		t.Fatalf("重複: %d", code)
	}
	if code := c.do("DELETE", "/v1/admins/"+b["id"].(string), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := iam.do("GET", "/v1/people", nil, nil); code != 401 {
		t.Fatalf("外したら使えない: %d", code)
	}
}

type fakeUI map[string]string // セッションのクッキー → アクセストークン

func (f fakeUI) Token(r *http.Request) (string, bool) {
	c, err := r.Cookie("s")
	if err != nil {
		return "", false
	}
	t, ok := f[c.Value]
	return t, ok
}

func TestUISession(t *testing.T) {
	c, _, _ := newServer(t, func(s *adminapi.Server) {
		s.UI = fakeUI{"iam": "iam-token", "static": secret}
	})
	get := func(cookie string) int {
		req, _ := http.NewRequest("GET", c.srv.URL+"/v1/me", nil)
		req.AddCookie(&http.Cookie{Name: "s", Value: cookie})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("iam"); code != 200 {
		t.Fatalf("IAM のセッション: %d", code)
	}
	// セッションに入っているのは IAM のトークンだけ。設定の鍵として扱わない。
	if code := get("static"); code != 401 {
		t.Fatalf("設定の鍵は通さない: %d", code)
	}
	if code := get("none"); code != 401 {
		t.Fatalf("知らないセッション: %d", code)
	}
}
