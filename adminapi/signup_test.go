package adminapi_test

import (
	"testing"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func withSignup(max int) func(*adminapi.Server) {
	return func(s *adminapi.Server) {
		s.Signup = adminapi.Signup{Enabled: true, MaxOrgsPerUser: max}
		s.Introspector = fakeIntrospector{
			"iam-token": {Active: true, Issuer: "https://iam.example", Subject: "user-1", Username: "boss@example.com"},
			"iam-2":     {Active: true, Issuer: "https://iam.example", Subject: "user-2", Username: "member@example.com"},
			"iam-3":     {Active: true, Issuer: "https://iam.example", Subject: "user-3", Username: "other@example.com"},
		}
	}
}

func TestSignup(t *testing.T) {
	c, _, _ := newServer(t, withSignup(2))
	iam := c.as("iam-token")
	var me map[string]any
	if code := iam.do("GET", "/v1/me", nil, &me); code != 200 || me["can_signup"] != true {
		t.Fatalf("me: %d %v", code, me)
	}
	var org map[string]any
	if code := iam.do("POST", "/v1/signup", map[string]any{"name": "すずき家"}, &org); code != 201 || org["kind"] != "family" {
		t.Fatalf("signup: %d %v", code, org)
	}
	id := org["id"].(string)
	// 作った人はその組織の管理者になり、その組織のものを作れる。
	if code := iam.do("GET", "/v1/me", nil, &me); code != 200 || len(me["roles"].([]any)) != 1 {
		t.Fatalf("me after signup: %v", me)
	}
	if code := iam.do("POST", "/v1/people", map[string]any{"name": "たろう"}, nil); code != 201 {
		t.Fatalf("自分の組織に人を足す: %d", code)
	}
	// ほかの組織は見えない。
	if code := iam.do("GET", "/v1/orgs/"+testkit.OrgID, nil, nil); code != 404 {
		t.Fatalf("ほかの組織: %d", code)
	}
	var orgs struct{ Orgs []map[string]any }
	iam.do("GET", "/v1/orgs", nil, &orgs)
	if len(orgs.Orgs) != 1 || orgs.Orgs[0]["id"] != id {
		t.Fatalf("orgs: %v", orgs)
	}
	for name, body := range map[string]map[string]any{
		"名前が無い":      {"name": " "},
		"知らない種類":     {"name": "x", "kind": "club"},
		"既定のポリシーは無い": {"name": "x", "default_policy_id": "pol"},
	} {
		if code := iam.do("POST", "/v1/signup", body, nil); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code := iam.do("POST", "/v1/signup", map[string]any{"name": "会社", "kind": "company"}, nil); code != 201 {
		t.Fatalf("2 つめ: %d", code)
	}
	if code := iam.do("POST", "/v1/signup", map[string]any{"name": "3 つめ"}, nil); code != 409 {
		t.Fatalf("上限: %d", code)
	}
	// 設定の鍵（誰なのかが IAM に無い）では作れない。
	if code := c.do("POST", "/v1/signup", map[string]any{"name": "x"}, nil); code != 403 {
		t.Fatalf("設定の鍵: %d", code)
	}
	var audit struct{ Events []map[string]any }
	c.do("GET", "/v1/audit", nil, &audit)
	signups := 0
	for _, e := range audit.Events {
		if e["action"] == "org.signup" && e["actor"] == "boss@example.com" {
			signups++
		}
	}
	if signups != 2 {
		t.Fatalf("操作の記録: %v", audit.Events)
	}
}

func TestSignupDisabled(t *testing.T) {
	c, _, _ := newServer(t)
	if code := c.as("iam-token").do("POST", "/v1/signup", map[string]any{"name": "x"}, nil); code != 403 {
		t.Fatalf("signup disabled: %d", code)
	}
}

func TestInvitation(t *testing.T) {
	c, _, clock := newServer(t, withSignup(0))
	boss, member, other := c.as("iam-token"), c.as("iam-2"), c.as("iam-3")
	var org map[string]any
	if code := boss.do("POST", "/v1/signup", map[string]any{"name": "すずき家"}, &org); code != 201 {
		t.Fatalf("signup: %d", code)
	}
	id := org["id"].(string)
	base := "/v1/orgs/" + id + "/invitations"

	var inv map[string]any
	if code := boss.do("POST", base, map[string]any{"label": "member@example.com"}, &inv); code != 201 || inv["role"] != "org_admin" || inv["code"] == nil {
		t.Fatalf("invite: %d %v", code, inv)
	}
	code := inv["code"].(string)
	var list struct{ Invitations []map[string]any }
	if c := boss.do("GET", base, nil, &list); c != 200 || len(list.Invitations) != 1 || list.Invitations[0]["code"] != nil {
		t.Fatalf("list（コードは返さない）: %d %v", c, list)
	}
	// ほかの組織の管理者・登録されていない人は招待を作れない。
	if c := c.as("mdm_org_admin").do("POST", base, map[string]any{}, nil); c != 404 {
		t.Fatalf("ほかの組織の管理者: %d", c)
	}
	if c := other.do("POST", base, map[string]any{}, nil); c != 401 {
		t.Fatalf("未登録: %d", c)
	}
	if c := boss.do("POST", base, map[string]any{"role": "server_admin"}, nil); c != 400 {
		t.Fatalf("server_admin には招待できない: %d", c)
	}

	if c := member.do("POST", "/v1/invitations/accept", map[string]any{"code": "mdminv_wrong"}, nil); c != 404 {
		t.Fatalf("違うコード: %d", c)
	}
	var b map[string]any
	if c := member.do("POST", "/v1/invitations/accept", map[string]any{"code": code}, &b); c != 201 || b["org_id"] != id || b["subject"] != "user-2" || b["role"] != "org_admin" {
		t.Fatalf("accept: %d %v", c, b)
	}
	if c := member.do("POST", "/v1/people", map[string]any{"name": "はなこ", "org_id": id}, nil); c != 201 {
		t.Fatalf("招待で管理者になった: %d", c)
	}
	// 1 回使ったコードはもう使えない。
	if c := other.do("POST", "/v1/invitations/accept", map[string]any{"code": code}, nil); c != 404 {
		t.Fatalf("使ったコード: %d", c)
	}
	if boss.do("GET", base, nil, &list); len(list.Invitations) != 0 {
		t.Fatalf("受けたら消える: %v", list)
	}

	// すでに管理者の人が受けても、招待は残る。
	var again map[string]any
	boss.do("POST", base, map[string]any{"role": "org_viewer"}, &again)
	if c := member.do("POST", "/v1/invitations/accept", map[string]any{"code": again["code"]}, nil); c != 409 {
		t.Fatalf("すでに管理者: %d", c)
	}
	var viewer map[string]any
	if c := other.do("POST", "/v1/invitations/accept", map[string]any{"code": again["code"]}, &viewer); c != 201 || viewer["role"] != "org_viewer" {
		t.Fatalf("見るだけで受ける: %d %v", c, viewer)
	}
	// 見るだけの管理者は招待を作れない・見られない。
	if c := other.do("POST", base, map[string]any{}, nil); c != 403 {
		t.Fatalf("見るだけ: %d", c)
	}

	// 期限が切れたら受けられない。消した招待も受けられない。
	var old, gone map[string]any
	boss.do("POST", base, map[string]any{}, &old)
	boss.do("POST", base, map[string]any{}, &gone)
	if c := boss.do("DELETE", base+"/"+gone["id"].(string), nil, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c := c.as("mdm_org_admin").do("DELETE", base+"/"+old["id"].(string), nil, nil); c != 404 {
		t.Fatalf("ほかの組織から消す: %d", c)
	}
	clock.Advance(7*24*time.Hour + time.Second)
	if boss.do("GET", base, nil, &list); len(list.Invitations) != 0 {
		t.Fatalf("期限切れは見せない: %v", list)
	}
	for _, x := range []map[string]any{old, gone} {
		if c := c.as("iam-3").do("POST", "/v1/invitations/accept", map[string]any{"code": x["code"]}, nil); c != 404 {
			t.Fatalf("期限切れ・消した: %d", c)
		}
	}
}
