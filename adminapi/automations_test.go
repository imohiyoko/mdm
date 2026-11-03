package adminapi_test

import (
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestAutomations(t *testing.T) {
	admin, store, clock := newServer(t)
	org := admin.as("mdm_org_admin")
	var pol, grp, per map[string]any
	if code := org.do("POST", "/v1/policies", map[string]any{"name": "勉強", "mode": "allowlist_only", "allow": []string{"school.example"}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if code := org.do("POST", "/v1/groups", map[string]any{"name": "子ども"}, &grp); code != 201 {
		t.Fatal(code)
	}
	pid, gid := pol["id"].(string), grp["id"].(string)
	if code := org.do("POST", "/v1/people", map[string]any{"name": "たろう", "group_ids": []string{gid}}, &per); code != 201 {
		t.Fatal(code, per)
	}
	var dev struct {
		Device map[string]any `json:"device"`
	}
	if code := org.do("POST", "/v1/devices", map[string]any{"name": "たろうの iPhone", "platform": "ios", "person_id": per["id"]}, &dev); code != 201 {
		t.Fatal(code, dev)
	}
	did := dev.Device["id"].(string)

	// 入力の誤り。
	for _, body := range []map[string]any{
		{"name": "x", "trigger": "schedule", "policy_id": pid},                                                     // 時間帯が無い
		{"name": "x", "trigger": "noncompliant", "policy_id": pid},                                                 // 理由が無い
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"sleepy"}, "policy_id": pid},                  // 知らない理由
		{"name": "x", "trigger": "weather", "policy_id": pid},                                                      // 知らない条件
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}},                             // ポリシーが無い
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "pol_missing"}, // 無いポリシー
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": pid, "group_ids": []string{"grp_missing"}},
		{"name": "x", "trigger": "schedule", "windows": []map[string]any{{"start": "19:00", "end": "21:00"}}, "time_zone": "Mars/Base", "policy_id": pid},
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "windows": []map[string]any{{"start": "19:00", "end": "21:00"}}, "policy_id": pid},
	} {
		if code := org.do("POST", "/v1/automations", body, nil); code != 400 {
			t.Errorf("%v: %d", body, code)
		}
	}

	// 平日の 19:00〜21:00（東京）は、子どもに勉強のポリシー。
	var a map[string]any
	body := map[string]any{"name": "宿題の時間", "group_ids": []string{gid}, "trigger": "schedule", "time_zone": "Asia/Tokyo", "policy_id": pid,
		"windows": []map[string]any{{"days": []string{"mon", "tue", "wed", "thu", "fri"}, "start": "19:00", "end": "21:00"}}}
	if code := org.do("POST", "/v1/automations", body, &a); code != 201 || a["enabled"] != true {
		t.Fatal(code, a)
	}
	aid := a["id"].(string)
	get := func() map[string]any {
		var got map[string]any
		org.do("GET", "/v1/devices/"+did, nil, &got)
		return got
	}
	if got := get(); got["automation_id"] != nil {
		t.Fatal(got)
	}
	clock.Set(time.Date(2026, 11, 3, 10, 30, 0, 0, time.UTC)) // 火曜 19:30 東京
	if got := get(); got["automation_id"] != aid || got["effective_policy_id"] != pid {
		t.Fatal(got)
	}

	// 止める（置き換えは全体を送る）。
	body["enabled"] = false
	if code := org.do("PUT", "/v1/automations/"+aid, body, &a); code != 200 || a["enabled"] != false {
		t.Fatal(code, a)
	}
	if got := get(); got["automation_id"] != nil {
		t.Fatal(got)
	}

	// 使っているポリシーとグループは消せない。
	if code := org.do("DELETE", "/v1/policies/"+pid, nil, nil); code != 409 {
		t.Fatal(code)
	}
	if code := org.do("PATCH", "/v1/people/"+per["id"].(string), map[string]any{"group_ids": []string{}}, nil); code != 200 {
		t.Fatal(code)
	}
	if code := org.do("DELETE", "/v1/groups/"+gid, nil, nil); code != 409 {
		t.Fatal(code)
	}

	// 見るだけの人は読めるが変えられない。
	viewer := admin.as("mdm_org_viewer")
	var list struct {
		Automations []map[string]any `json:"automations"`
	}
	if code := viewer.do("GET", "/v1/automations", nil, &list); code != 200 || len(list.Automations) != 1 {
		t.Fatal(code, list)
	}
	if code := viewer.do("DELETE", "/v1/automations/"+aid, nil, nil); code != 403 {
		t.Fatal(code)
	}

	// 記録が残る。
	evs, _ := store.ListAudit(t.Context(), 50)
	n := 0
	for _, e := range evs {
		if e.Target == aid {
			n++
		}
	}
	if n != 2 {
		t.Fatal(evs)
	}
	if code := org.do("DELETE", "/v1/automations/"+aid, nil, nil); code != 204 {
		t.Fatal(code)
	}
	if code := org.do("DELETE", "/v1/groups/"+gid, nil, nil); code != 204 {
		t.Fatal(code)
	}
}

// ほかの組織の自動のルールは見えない。ほかの組織のポリシー・グループは使えない。
func TestAutomationsOtherOrg(t *testing.T) {
	admin, store, _ := newServer(t)
	ctx := t.Context()
	if err := store.CreateOrg(ctx, core.Org{ID: "org2", Name: "別", Kind: core.OrgCompany}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePolicy(ctx, core.Policy{ID: "pol2", OrgID: "org2", Name: "別の", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateGroup(ctx, core.Group{ID: "grp2", OrgID: "org2", Name: "別の"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAutomation(ctx, core.Automation{ID: "aut2", OrgID: "org2", Name: "別の", Enabled: true,
		Trigger: core.TriggerNoncompliant, Reasons: []string{"not_encrypted"}, PolicyID: "pol2"}); err != nil {
		t.Fatal(err)
	}
	org := admin.as("mdm_org_admin")
	if code := org.do("GET", "/v1/automations/aut2", nil, nil); code != 404 {
		t.Fatal(code)
	}
	if code := org.do("PUT", "/v1/automations/aut2", map[string]any{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "pol2"}, nil); code != 404 {
		t.Fatal(code)
	}
	var list struct {
		Automations []map[string]any `json:"automations"`
	}
	if org.do("GET", "/v1/automations", nil, &list); len(list.Automations) != 0 {
		t.Fatal(list)
	}
	for _, body := range []map[string]any{
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "pol2"},
		{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "default", "group_ids": []string{"grp2"}},
		{"org_id": "org2", "name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "default"},
	} {
		if code := org.do("POST", "/v1/automations", body, nil); code == 201 {
			t.Errorf("%v: %d", body, code)
		}
	}
	// 組織 org1 では、サーバー全体の既定のポリシーは使える。
	if code := org.do("POST", "/v1/automations", map[string]any{"org_id": testkit.OrgID, "name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "default"}, nil); code != 201 {
		t.Fatal(code)
	}
}

func TestAutomationsLimit(t *testing.T) {
	admin, _, _ := newServer(t)
	org := admin.as("mdm_org_admin")
	body := map[string]any{"name": "x", "trigger": "noncompliant", "reasons": []string{"not_encrypted"}, "policy_id": "default"}
	for i := 0; i < 50; i++ {
		if code := org.do("POST", "/v1/automations", body, nil); code != 201 {
			t.Fatal(i, code)
		}
	}
	var e map[string]any
	if code := org.do("POST", "/v1/automations", body, &e); code != 409 || e["error"] != "limit_exceeded" {
		t.Fatal(code, e)
	}
}
