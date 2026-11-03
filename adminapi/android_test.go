package adminapi_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/android/androidtest"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestAndroidNotConfigured(t *testing.T) {
	c, _, _ := newServer(t)
	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "a", "platform": "android"}, &dev)
	if code := c.do("POST", "/v1/devices/"+dev.Device["id"].(string)+"/enroll", map[string]any{}, nil); code != 501 {
		t.Fatal(code)
	}
	if code := c.do("POST", "/v1/orgs/"+testkit.OrgID+"/android/signup", map[string]any{}, nil); code != 501 {
		t.Fatal(code)
	}
}

func TestAndroidFlow(t *testing.T) {
	fake, amapi := androidtest.New(t)
	var svc *android.Service
	c, store, _ := newServer(t, func(s *adminapi.Server) {
		svc = &android.Service{Store: s.Store, Client: amapi, Engine: s.Engine, Clock: s.Clock, ProjectID: "proj",
			CallbackURL: "https://mdm.example" + android.CallbackPath, DoTDomain: "dns.example"}
		s.Android = svc
	})
	ctx := context.Background()

	// 見るだけの管理者は始められない。
	if code := c.as("mdm_org_viewer").do("POST", "/v1/orgs/"+testkit.OrgID+"/android/signup", map[string]any{}, nil); code != 403 {
		t.Fatal(code)
	}
	var su map[string]any
	if code := c.as("mdm_org_admin").do("POST", "/v1/orgs/"+testkit.OrgID+"/android/signup", map[string]any{"admin_email": "boss@example.com"}, &su); code != 200 || su["url"] == "" {
		t.Fatal(code, su)
	}

	// Google の画面から戻ってくる。
	cb := httptest.NewServer(svc.CallbackHandler())
	defer cb.Close()
	u, _ := url.Parse(fake.CallbackURL)
	resp, err := http.Get(cb.URL + "?" + url.Values{"state": {u.Query().Get("state")}, "enterpriseToken": {androidtest.EnterpriseToken}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "始めました") {
		t.Fatal(resp.StatusCode, string(b))
	}
	var st map[string]any
	if c.do("GET", "/v1/orgs/"+testkit.OrgID+"/android", nil, &st); st["started"] != true || st["enterprise"] != "enterprises/LC0test" {
		t.Fatal(st)
	}

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "子ども",
		"device":       map[string]any{"factory_reset_disabled": true, "passcode_min_length": 4},
		"android_apps": map[string]any{"mode": "open", "blocked": []string{"com.example.game"}},
	}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if pol["device"].(map[string]any)["factory_reset_disabled"] != true || pol["android_apps"].(map[string]any)["blocked"].([]any)[0] != "com.example.game" {
		t.Fatal(pol)
	}
	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "タブレット", "platform": "android", "policy_id": pol["id"]}, &dev)
	id := dev.Device["id"].(string)
	before, _ := store.GetDevice(ctx, id)

	var en struct{ Enrollment android.Enrollment }
	if code := c.do("POST", "/v1/devices/"+id+"/enroll", map[string]any{"mode": "fully_managed"}, &en); code != 200 || en.Enrollment.QRCode == "" || !en.Enrollment.FilterEnforced {
		t.Fatal(code, en)
	}
	after, _ := store.GetDevice(ctx, id)
	if string(after.DoTLabelHash) == string(before.DoTLabelHash) {
		t.Fatal("dot label not rotated")
	}
	// ポリシーに書いたホスト名のラベルで、DoT の端末が見つかる。
	host := fake.Policy("enterprises/LC0test/policies/" + id)["deviceConnectivityManagement"].(map[string]any)["privateDnsSettings"].(map[string]any)["privateDnsHost"].(string)
	label, _ := strings.CutSuffix(host, ".dns.example")
	if err := svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if d, err := svc.Engine.DeviceByDoTLabel(ctx, label); err != nil || d.ID != id {
		t.Fatal(d, err)
	}

	fake.SetDevices(android.Device{Name: "enterprises/LC0test/devices/D1", State: "ACTIVE", ManagementMode: "DEVICE_OWNER",
		PolicyName: "enterprises/LC0test/policies/" + id, EnrollmentTokenData: id})
	if err := svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	c.do("GET", "/v1/devices/"+id, nil, &got)
	if m := got["managed"].(map[string]any); m["state"] != "active" || m["mode"] != "fully_managed" {
		t.Fatal(got)
	}

	if code := c.do("DELETE", "/v1/devices/"+id, nil, nil); code != 409 {
		t.Fatal("delete managed:", code)
	}
	if code := c.do("PATCH", "/v1/devices/"+id, map[string]any{"platform": "ios"}, nil); code != 409 {
		t.Fatal("platform change:", code)
	}
	if code := c.as("mdm_org_viewer").do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "lock"}, nil); code != 403 {
		t.Fatal(code)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "lock"}, nil); code != 202 || len(fake.Commands) != 1 {
		t.Fatal(code, fake.Commands)
	}

	// ポリシーを変えると配り直す（ふつうは後ろで Kick されて配る。ここでは直接呼ぶ）。
	polID := pol["id"].(string)
	if code := c.do("PUT", "/v1/policies/"+polID, map[string]any{"name": "子ども",
		"android_apps": map[string]any{"mode": "allowlist", "allowed": []string{"com.example.reader"}}}, nil); code != 200 {
		t.Fatal(code)
	}
	if err := svc.PushAll(ctx); err != nil {
		t.Fatal(err)
	}
	if p := fake.Policy("enterprises/LC0test/policies/" + id); p["playStoreMode"] != "WHITELIST" {
		t.Fatal(p)
	}

	// DoT のラベルを作り直すと、端末のホスト名も変わる。
	var rot struct{ Filter map[string]string }
	if code := c.do("POST", "/v1/devices/"+id+"/filter-token", nil, &rot); code != 200 {
		t.Fatal(code)
	}
	host2 := fake.Policy("enterprises/LC0test/policies/" + id)["deviceConnectivityManagement"].(map[string]any)["privateDnsSettings"].(map[string]any)["privateDnsHost"]
	if host2 != rot.Filter["dot_hostname"] || host2 == host {
		t.Fatal(host2, rot.Filter)
	}
	// 配れなければ元に戻す。
	fake.Fail = "PATCH policies"
	if code := c.do("POST", "/v1/devices/"+id+"/filter-token", nil, nil); code != 502 {
		t.Fatal(code)
	}
	fake.Fail = ""
	label2, _ := strings.CutSuffix(host2.(string), ".dns.example")
	if err := svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if d, err := svc.Engine.DeviceByDoTLabel(ctx, label2); err != nil || d.ID != id {
		t.Fatal("label not restored:", d, err)
	}

	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{}, nil); code != 400 {
		t.Fatal("wipe without confirm:", code)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{"confirm_wipe": true}, nil); code != 204 {
		t.Fatal(code)
	}
	if code := c.do("DELETE", "/v1/devices/"+id, nil, nil); code != 204 {
		t.Fatal("delete after unenroll:", code)
	}
	if _, err := store.GetManaged(ctx, id); err != core.ErrNotFound {
		t.Fatal(err)
	}
}

func TestPolicyAppValidation(t *testing.T) {
	c, _, _ := newServer(t)
	for _, apps := range []map[string]any{
		{"mode": "closed"},
		{"blocked": []string{"not a package"}},
		{"blocked": []string{"com.a.b"}, "required": []string{"com.a.b"}},
	} {
		if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "android_apps": apps}, nil); code != 400 {
			t.Fatal(apps, code)
		}
	}
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "device": map[string]any{"passcode_min_length": 17}}, nil); code != 400 {
		t.Fatal(code)
	}
}
