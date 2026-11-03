package adminapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/apple"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

type countPusher struct {
	mu sync.Mutex
	n  int
}

func (p *countPusher) Push(context.Context, []byte, string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	return nil
}

func TestAppleAPI(t *testing.T) {
	ca, err := pki.NewCA("t", 2048)
	if err != nil {
		t.Fatal(err)
	}
	push := &countPusher{}
	c, store, _ := newServer(t, func(s *adminapi.Server) {
		s.Apple = &apple.Service{Store: s.Store, Engine: s.Engine, Clock: s.Clock, CA: ca, Pusher: push,
			Topic: "com.apple.mgmt.External.t", BaseURL: "https://mdm.example", DoHBaseURL: "https://dns.example"}
	})
	ctx := context.Background()

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "iPhone",
		"apple_apps": map[string]any{"mode": "allowlist", "allowed": []string{"com.apple.mobilesafari", "jp.co.example-app.ios"}}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if a := pol["apple_apps"].(map[string]any); a["mode"] != "allowlist" || len(a["allowed"].([]any)) != 2 {
		t.Fatal(pol)
	}
	for _, apps := range []map[string]any{{"required": []string{"com.a.b"}}, {"blocked": []string{"nodot"}}, {"mode": "x"}} {
		if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "apple_apps": apps}, nil); code != 400 {
			t.Fatal(apps, code)
		}
	}

	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "iPhone", "platform": "ios"}, &dev)
	id := dev.Device["id"].(string)
	if code := c.do("POST", "/v1/devices/"+id+"/enroll", map[string]any{"mode": "work_profile"}, nil); code != 400 {
		t.Fatal("mode for apple:", code)
	}
	var en struct{ Enrollment apple.Enrollment }
	if code := c.do("POST", "/v1/devices/"+id+"/enroll", map[string]any{}, &en); code != 200 ||
		!strings.HasPrefix(en.Enrollment.ProfileURL, "https://mdm.example/apple/enroll/") {
		t.Fatal(code, en)
	}

	// 登録が済んだことにする。
	if err := store.PutManaged(ctx, core.Managed{DeviceID: id, Provider: apple.Provider, State: core.ManagedActive,
		PushToken: "00ff", PushMagic: "magic", CertFingerprints: []string{"x"}, Supervised: true, FilterManaged: true}); err != nil {
		t.Fatal(err)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "wipe"}, nil); code != 400 {
		t.Fatal("wipe without confirm:", code)
	}
	for _, typ := range []string{"lock", "reboot"} {
		if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": typ}, nil); code != 202 {
			t.Fatal(typ, code)
		}
	}
	if code := c.do("POST", "/v1/devices/"+id+"/filter-token", nil, nil); code != 200 {
		t.Fatal("rotate:", code)
	}
	var cmds struct{ Commands []map[string]any }
	c.do("GET", "/v1/devices/"+id+"/commands", nil, &cmds)
	purposes := map[any]bool{}
	for _, x := range cmds.Commands {
		purposes[x["purpose"]] = true
	}
	if !purposes["lock"] || !purposes["restart"] || !purposes["dns"] {
		t.Fatal(cmds)
	}
	if push.n < 3 {
		t.Fatal("push:", push.n)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{}, nil); code != 202 {
		t.Fatal(code)
	}
	if m, _ := store.GetManaged(ctx, id); m.State != core.ManagedUnenrolling {
		t.Fatal(m.State)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{"force": true}, nil); code != 204 {
		t.Fatal(code)
	}
}
