package adminapi_test

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/imohiyoko/API/cli"
	"github.com/imohiyoko/API/define"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

// newRules は管理の API と、同じサーバーのルールの API を返す。
func newRules(t *testing.T) (admin, rules client, store core.Store) {
	t.Helper()
	var srv *adminapi.Server
	admin, store, _ = newServer(t, func(s *adminapi.Server) { srv = s })
	api, err := srv.RulesAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(api.Handler(define.Public))
	t.Cleanup(hs.Close)
	return admin, client{t: t, srv: hs}, store
}

func TestRulesPolicyLifecycle(t *testing.T) {
	admin, rules, store := newRules(t)
	org := rules.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID + "/policies"

	// 試しに作る（保存しない）。
	spec := map[string]any{"name": "小学生", "block": []string{"*.game.example", "video.example"}, "allow": []string{"school.example"},
		"quiet_hours": []map[string]any{{"start": "21:00", "end": "07:00"}}, "time_zone": "Asia/Tokyo"}
	var res struct {
		Policy struct {
			ID      string         `json:"id"`
			Version string         `json:"version"`
			Policy  map[string]any `json:"policy"`
		} `json:"policy"`
		Changes []map[string]any `json:"changes"`
		Applied bool             `json:"applied"`
	}
	if code := org.do("POST", base, map[string]any{"policy": spec, "dry_run": true}, &res); code != 200 || res.Applied || len(res.Changes) == 0 {
		t.Fatal(code, res)
	}
	if ps, _ := store.ListPolicies(t.Context()); len(ps) != 1 {
		t.Fatal("dry run saved", ps)
	}
	if code := org.do("POST", base, map[string]any{"policy": spec}, &res); code != 200 || !res.Applied {
		t.Fatal(code, res)
	}
	id, v1 := res.Policy.ID, res.Policy.Version
	if res.Policy.Policy["block"].([]any)[0] != "game.example" { // 管理の API と同じ形に直す
		t.Fatal(res.Policy.Policy)
	}

	// 同じ中身で置き換えても、変わらない（何度 apply しても同じ）。
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": spec, "expected_version": v1}, &res); code != 200 || res.Applied || len(res.Changes) != 0 || res.Policy.Version != v1 {
		t.Fatal(code, res)
	}

	// 差分（plan）：ブロックに 1 つ足し、時間帯を消す。
	spec2 := map[string]any{"name": "小学生", "block": []string{"game.example", "video.example", "sns.example"}, "allow": []string{"school.example"}, "time_zone": "Asia/Tokyo"}
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": spec2, "dry_run": true}, &res); code != 200 || res.Applied {
		t.Fatal(code, res)
	}
	fields := map[string]map[string]any{}
	for _, c := range res.Changes {
		fields[c["field"].(string)] = c
	}
	if len(fields) != 2 || fields["block"]["added"].([]any)[0] != "sns.example" || fields["quiet_hours"] == nil {
		t.Fatal(res.Changes)
	}

	// 管理画面で先に変えられていたら、古い版では書き込まない。
	if code := admin.do("PUT", "/v1/policies/"+id, map[string]any{"name": "小学生", "block": []string{"x.example"}}, nil); code != 200 {
		t.Fatal(code)
	}
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": spec2, "expected_version": v1}, &res); code != 412 {
		t.Fatal(code)
	}
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": spec2}, &res); code != 200 || !res.Applied {
		t.Fatal(code, res)
	}
	p, _ := store.GetPolicy(t.Context(), id)
	if len(p.Block) != 3 || len(p.Quiet) != 0 {
		t.Fatal(p)
	}

	// ドメインを足す・消す。
	if code := org.do("POST", "/v1/policies/"+id+"/edit", map[string]any{"add_block": []string{"*.ads.example"}, "remove_block": []string{"video.example"}}, &res); code != 200 || !res.Applied {
		t.Fatal(code, res)
	}
	p, _ = store.GetPolicy(t.Context(), id)
	if len(p.Block) != 3 || p.Block[2] != "ads.example" {
		t.Fatal(p.Block)
	}

	// 入力の誤りは直し方が分かるように返す。
	var e map[string]any
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": map[string]any{"name": "x", "block": []string{"not a domain"}}}, &e); code != 400 {
		t.Fatal(code, e)
	}

	// 一覧と読むこと。見るだけの人は読めるが変えられない。
	var list []map[string]any
	viewer := rules.as("mdm_org_viewer")
	if code := viewer.do("GET", base, nil, &list); code != 200 || len(list) != 1 {
		t.Fatal(code, list)
	}
	if code := viewer.do("POST", "/v1/policies/"+id+"/edit", map[string]any{"add_block": []string{"a.example"}}, nil); code != 403 {
		t.Fatal(code)
	}
	for _, tok := range []string{"nope", "iam-token"} { // 知らない鍵・役割の無い IAM のユーザー
		if code := rules.as(tok).do("GET", base, nil, nil); code != 401 {
			t.Fatal(tok, code)
		}
	}
	// ファイルの書き間違い（知らない項目）は断る。
	if code := org.do("PUT", "/v1/policies/"+id, map[string]any{"policy": map[string]any{"name": "x", "blok": []string{"a.example"}}}, nil); code != 400 {
		t.Fatal(code)
	}
}

// ほかの組織のポリシー・端末は、読むことも変えることもできない。サーバー全体の既定のポリシーも変えられない。
func TestRulesOtherOrg(t *testing.T) {
	admin, rules, store := newRules(t)
	var other map[string]any
	admin.do("POST", "/v1/orgs", map[string]any{"name": "別の会社", "kind": "company"}, &other)
	oid := other["id"].(string)
	var pol map[string]any
	if code := admin.do("POST", "/v1/policies", map[string]any{"org_id": oid, "name": "社"}, &pol); code != 201 {
		t.Fatal(code)
	}
	var dev struct {
		Device map[string]any `json:"device"`
	}
	if code := admin.do("POST", "/v1/devices", map[string]any{"org_id": oid, "name": "社の PC", "platform": "windows"}, &dev); code != 201 {
		t.Fatal(code, dev)
	}
	org := rules.as("mdm_org_admin")
	pid, did := pol["id"].(string), dev.Device["id"].(string)
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/orgs/" + oid + "/policies", nil},
		{"GET", "/v1/orgs/" + oid + "/devices", nil},
		{"POST", "/v1/orgs/" + oid + "/policies", map[string]any{"policy": map[string]any{"name": "x"}}},
		{"GET", "/v1/policies/" + pid, nil},
		{"POST", "/v1/policies/" + pid + "/edit", map[string]any{"add_block": []string{"a.example"}}},
		{"PUT", "/v1/policies/" + pid, map[string]any{"policy": map[string]any{"name": "x"}}},
		{"POST", "/v1/devices/" + did + "/pause", map[string]any{"minutes": 10}},
		{"DELETE", "/v1/devices/" + did + "/pause", nil},
		{"PUT", "/v1/policies/pol_default", map[string]any{"policy": map[string]any{"name": "x"}}},
		{"GET", "/v1/policies/pol_missing", nil}, // 無いものも同じ答え（有るかどうかを見せない）
	} {
		if code := org.do(tc.method, tc.path, tc.body, nil); code != 403 {
			t.Errorf("%s %s: %d", tc.method, tc.path, code)
		}
	}
	p, _ := store.GetPolicy(t.Context(), pid)
	if p.Name != "社" {
		t.Fatal(p)
	}
}

func TestRulesPause(t *testing.T) {
	admin, rules, store := newRules(t)
	var dev struct {
		Device map[string]any `json:"device"`
	}
	if code := admin.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "たろうの iPhone", "platform": "ios"}, &dev); code != 201 {
		t.Fatal(code, dev)
	}
	id := dev.Device["id"].(string)
	org := rules.as("mdm_org_admin")
	var out map[string]any
	if code := org.do("POST", "/v1/devices/"+id+"/pause", map[string]any{"minutes": 30}, &out); code != 200 || out["paused_until"] == nil {
		t.Fatal(code, out)
	}
	if code := org.do("POST", "/v1/devices/"+id+"/pause", map[string]any{"minutes": 0}, nil); code != 400 {
		t.Fatal(code)
	}
	var list []map[string]any
	if org.do("GET", "/v1/orgs/"+testkit.OrgID+"/devices", nil, &list); len(list) != 1 || list[0]["paused_until"] == nil {
		t.Fatal(list)
	}
	if code := org.do("DELETE", "/v1/devices/"+id+"/pause", nil, &out); code != 200 || out["paused_until"] != nil {
		t.Fatal(code, out)
	}
	d, _ := store.GetDevice(t.Context(), id)
	if !d.PausedUntil.IsZero() {
		t.Fatal(d.PausedUntil)
	}
	evs, _ := store.ListAudit(t.Context(), 50)
	found := false
	for _, e := range evs {
		if e.Action == "device.pause" && e.Actor == "org-admin（ルールの API）" {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit", evs)
	}
}

// 置いてある契約（api/rules）が定義と食い違っていない。変えたら mdm rules-api gen -out api/rules で作り直す。
func TestRulesContractUpToDate(t *testing.T) {
	m, err := (&adminapi.Server{}).RulesRegistry().Manifest()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := cli.Run(m, []string{"gen", "-out", dir, "-title", adminapi.RulesAPITitle, "-version", adminapi.RulesAPIVersion}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	for _, f := range []string{"manifest.json", "openapi/public.json"} {
		want, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("..", "api", "rules", f))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("api/rules/%s が古い。mdm rules-api gen -out api/rules で作り直す", f)
		}
	}
}

// 組織の上限は 409（412 は版の食い違いだけ）。
func TestRulesQuota(t *testing.T) {
	var srv *adminapi.Server
	newServer(t, func(s *adminapi.Server) { srv = s; s.Limits = core.OrgLimits{Policies: 1} })
	api, err := srv.RulesAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(api.Handler(define.Public))
	t.Cleanup(hs.Close)
	org := client{t: t, srv: hs}.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID + "/policies"
	if code := org.do("POST", base, map[string]any{"policy": map[string]any{"name": "a"}}, nil); code != 200 {
		t.Fatal(code)
	}
	if code := org.do("POST", base, map[string]any{"policy": map[string]any{"name": "b"}}, nil); code != 409 {
		t.Fatal(code)
	}
}
