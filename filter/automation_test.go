package filter_test

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
)

// 自動のルールは、当たっているあいだだけポリシーを切り替え、外れたら元に戻る。
func TestAutomations(t *testing.T) {
	f := setup(t)
	ctx := f.ctx
	f.must(f.store.CreatePolicy(ctx, core.Policy{ID: "normal", OrgID: testkit.OrgID, Name: "ふだん", Mode: core.FilterBlocklist,
		Compliance: core.ComplianceRules{RequireEncryption: true}}))
	f.must(f.store.CreatePolicy(ctx, core.Policy{ID: "study", OrgID: testkit.OrgID, Name: "勉強", Mode: core.FilterAllowlistOnly, Allow: []string{"school.example"}}))
	f.must(f.store.CreatePolicy(ctx, core.Policy{ID: "locked", OrgID: testkit.OrgID, Name: "止める", Mode: core.FilterAllowlistOnly}))
	f.must(f.store.CreateGroup(ctx, core.Group{ID: "kids", OrgID: testkit.OrgID, Name: "子ども"}))
	f.must(f.store.CreatePerson(ctx, core.Person{ID: "taro", OrgID: testkit.OrgID, Name: "たろう", Role: core.RoleChild, GroupIDs: []string{"kids"}}))
	f.must(f.store.CreatePerson(ctx, core.Person{ID: "mama", OrgID: testkit.OrgID, Name: "母", Role: core.RoleAdult}))
	kid := f.device("kid", "taro", "normal")
	mom := f.device("mom", "mama", "normal")

	// 平日 19:00〜21:00（東京）は、子どもだけ勉強のポリシー。
	f.must(f.store.CreateAutomation(ctx, core.Automation{ID: "aut_study", OrgID: testkit.OrgID, Name: "宿題の時間", Enabled: true,
		GroupIDs: []string{"kids"}, Trigger: core.TriggerSchedule, TimeZone: "Asia/Tokyo", PolicyID: "study",
		Windows: []core.Window{{Days: []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}, Start: 19 * 60, End: 21 * 60}}}))
	// 暗号化していない端末は、誰でも止める（優先度が高い）。
	f.must(f.store.CreateAutomation(ctx, core.Automation{ID: "aut_lock", OrgID: testkit.OrgID, Name: "暗号化していない", Enabled: true, Priority: 10,
		Trigger: core.TriggerNoncompliant, Reasons: []string{"not_encrypted"}, PolicyID: "locked"}))
	// 止めてあるルールは効かない。
	f.must(f.store.CreateAutomation(ctx, core.Automation{ID: "aut_off", OrgID: testkit.OrgID, Name: "使わない", Enabled: false, Priority: 100,
		Trigger: core.TriggerSchedule, Windows: []core.Window{{Start: 0, End: 23*60 + 59}}, PolicyID: "locked"}))
	f.must(f.engine.Refresh(ctx))

	policy := func(d core.Device) string {
		t.Helper()
		p, _, err := f.engine.PolicyFor(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	// 月曜 12:00 東京：どれも当たらない。
	if policy(kid) != "normal" || policy(mom) != "normal" {
		t.Fatal(policy(kid), policy(mom))
	}
	// 月曜 19:30 東京：子どもだけ切り替わる。
	f.clock.Set(time.Date(2026, 11, 2, 10, 30, 0, 0, time.UTC))
	if policy(kid) != "study" || policy(mom) != "normal" {
		t.Fatal(policy(kid), policy(mom))
	}
	if d := f.decide(t, kid, "game.example"); d.Action != core.ActionBlock || d.Reason != filter.ReasonNotAllowed {
		t.Fatal(d)
	}
	if d := f.decide(t, kid, "school.example"); d.Action != core.ActionAllow {
		t.Fatal(d)
	}
	if id, _ := f.engine.AutomationFor(ctx, kid); id != "aut_study" {
		t.Fatal(id)
	}
	act, err := f.engine.ActiveAutomations(ctx)
	if err != nil || len(act) != 1 || act["kid"] != "aut_study" {
		t.Fatal(act, err)
	}

	// 準拠していない（暗号化していない）と、優先度の高いルールが勝つ。理由が違えば当たらない。
	f.must(f.store.PutCompliance(ctx, core.DeviceCompliance{DeviceID: "kid", Reasons: []string{"not_encrypted"}}))
	f.must(f.store.PutCompliance(ctx, core.DeviceCompliance{DeviceID: "mom", Reasons: []string{"os_outdated"}}))
	f.must(f.engine.Refresh(ctx))
	if policy(kid) != "locked" || policy(mom) != "normal" {
		t.Fatal(policy(kid), policy(mom))
	}
	// 準拠の判定は元のポリシーの条件で行う。
	if p, _, _ := f.engine.BasePolicyFor(ctx, kid); p.ID != "normal" {
		t.Fatal(p.ID)
	}

	// 直ったら、時間帯の外では元に戻る。
	f.must(f.store.PutCompliance(ctx, core.DeviceCompliance{DeviceID: "kid", Compliant: true}))
	f.must(f.engine.Refresh(ctx))
	f.clock.Set(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)) // 21:00 東京
	if policy(kid) != "normal" {
		t.Fatal(policy(kid))
	}

	// ほかの組織のポリシーを指していたら、使わない（元のポリシーのまま）。
	f.must(f.store.CreateOrg(ctx, core.Org{ID: "org2", Name: "別", Kind: core.OrgCompany}))
	f.must(f.store.CreatePolicy(ctx, core.Policy{ID: "other", OrgID: "org2", Name: "別の", Mode: core.FilterAllowlistOnly}))
	a, _ := f.store.GetAutomation(ctx, "aut_off")
	a.Enabled, a.PolicyID = true, "other"
	f.must(f.store.UpdateAutomation(ctx, a))
	f.must(f.engine.Refresh(ctx))
	if policy(kid) != "normal" {
		t.Fatal(policy(kid))
	}
}

func TestWatchAutomations(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	f.must(f.store.CreatePolicy(ctx, core.Policy{ID: "night", OrgID: testkit.OrgID, Name: "夜", Mode: core.FilterAllowlistOnly}))
	f.device("d1", "", "")
	f.must(f.store.CreateAutomation(ctx, core.Automation{ID: "aut", OrgID: testkit.OrgID, Name: "夜", Enabled: true,
		Trigger: core.TriggerSchedule, Windows: []core.Window{{Start: 4 * 60, End: 5 * 60}}, PolicyID: "night"}))
	f.must(f.engine.Refresh(ctx))
	kicked := make(chan struct{}, 10)
	go f.engine.WatchAutomations(ctx, 5*time.Millisecond, func() { kicked <- struct{}{} })
	time.Sleep(30 * time.Millisecond)
	select {
	case <-kicked:
		t.Fatal("変わっていないのに呼んだ")
	default:
	}
	f.clock.Set(time.Date(2026, 11, 2, 4, 0, 0, 0, time.UTC)) // 時間帯が始まる
	select {
	case <-kicked:
	case <-time.After(2 * time.Second):
		t.Fatal("呼ばれない")
	}
}
