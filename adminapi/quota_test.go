package adminapi_test

import (
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestOrgLimits(t *testing.T) {
	c, _, _ := newServer(t, func(s *adminapi.Server) { s.Limits = core.OrgLimits{Devices: 2, People: 1} })
	a := c.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID

	var u struct {
		Usage        map[string]int
		Limits       map[string]int
		CustomLimits bool `json:"custom_limits"`
	}
	if code := c.as("mdm_org_viewer").do("GET", base+"/usage", nil, &u); code != 200 || u.Limits["devices"] != 2 || u.Limits["groups"] != 0 || u.CustomLimits {
		t.Fatalf("usage: %d %+v", code, u)
	}
	before := u.Usage["devices"]
	for i := before; i < 2; i++ {
		if code := a.do("POST", "/v1/devices", map[string]any{"name": "d", "platform": "other"}, nil); code != 201 {
			t.Fatalf("device %d: %d", i, code)
		}
	}
	var e map[string]any
	if code := a.do("POST", "/v1/devices", map[string]any{"name": "d", "platform": "other"}, &e); code != 409 || e["error"] != "limit_exceeded" {
		t.Fatalf("上限の端末: %d %v", code, e)
	}
	a.do("GET", base+"/usage", nil, &u)
	if u.Usage["devices"] != 2 {
		t.Fatalf("usage after: %+v", u)
	}
	if u.Usage["people"] < 1 {
		if code := a.do("POST", "/v1/people", map[string]any{"name": "p"}, nil); code != 201 {
			t.Fatalf("person: %d", code)
		}
	}
	if code := a.do("POST", "/v1/people", map[string]any{"name": "p2"}, nil); code != 409 {
		t.Fatalf("上限の人: %d", code)
	}
	// 上限の無いもの（グループ）は作れる。
	if code := a.do("POST", "/v1/groups", map[string]any{"name": "g"}, nil); code != 201 {
		t.Fatalf("group: %d", code)
	}

	// 組織の管理者は上限を変えられない。サーバー全体の管理者は変えられる。
	if code := a.do("PUT", base+"/limits", map[string]any{"devices": 100}, nil); code != 403 {
		t.Fatalf("組織の管理者が上限を変える: %d", code)
	}
	if code := c.do("PUT", base+"/limits", map[string]any{"devices": -1}, nil); code != 400 {
		t.Fatalf("負: %d", code)
	}
	if code := c.do("PUT", base+"/limits", map[string]any{"devices": 3, "groups": 1}, nil); code != 200 {
		t.Fatalf("put limits: %d", code)
	}
	if code := a.do("POST", "/v1/devices", map[string]any{"name": "d", "platform": "other"}, nil); code != 201 {
		t.Fatalf("上限を上げたら作れる: %d", code)
	}
	if code := a.do("POST", "/v1/people", map[string]any{"name": "p3"}, nil); code != 201 {
		t.Fatalf("組織ごとの上限で人は上限なし: %d", code)
	}
	if code := a.do("POST", "/v1/groups", map[string]any{"name": "g2"}, nil); code != 409 {
		t.Fatalf("グループの上限: %d", code)
	}
	if code := a.do("POST", "/v1/policies", map[string]any{"name": "pol", "mode": "blocklist"}, nil); code != 201 {
		t.Fatalf("policy: %d", code)
	}
	a.do("GET", base+"/usage", nil, &u)
	if !u.CustomLimits || u.Limits["devices"] != 3 {
		t.Fatalf("custom: %+v", u)
	}
	if code := c.do("DELETE", base+"/limits", nil, nil); code != 204 {
		t.Fatalf("reset: %d", code)
	}
	if code := a.do("POST", "/v1/devices", map[string]any{"name": "d", "platform": "other"}, nil); code != 409 {
		t.Fatalf("既定に戻した: %d", code)
	}
	if code := c.as("mdm_org_admin").do("GET", "/v1/orgs/org-other/usage", nil, nil); code != 404 {
		t.Fatalf("ほかの組織: %d", code)
	}
}
