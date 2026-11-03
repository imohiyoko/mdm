package adminapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
	"github.com/imohiyoko/mdm/windows"
)

func TestWindowsAPI(t *testing.T) {
	ca, err := pki.NewCA("t", 2048)
	if err != nil {
		t.Fatal(err)
	}
	var svc *windows.Service
	c, store, _ := newServer(t, func(s *adminapi.Server) {
		svc = &windows.Service{Store: s.Store, Engine: s.Engine, Clock: s.Clock, CA: ca, BaseURL: "https://mdm.example"}
		s.Windows = svc
	})
	ctx := context.Background()

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "PC",
		"windows_apps": map[string]any{"blocked": []string{"Microsoft.MinecraftUWP"}}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if pol["windows_apps"].(map[string]any)["blocked"].([]any)[0] != "Microsoft.MinecraftUWP" {
		t.Fatal(pol)
	}
	for _, apps := range []map[string]any{{"mode": "allowlist"}, {"required": []string{"A.B"}}, {"blocked": []string{"bad name"}}} {
		if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "windows_apps": apps}, nil); code != 400 {
			t.Fatal(apps, code)
		}
	}

	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "PC", "platform": "windows"}, &dev)
	id := dev.Device["id"].(string)
	if code := c.do("POST", "/v1/devices/"+id+"/enroll", map[string]any{"mode": "work_profile"}, nil); code != 400 {
		t.Fatal("mode for windows:", code)
	}
	var en struct{ Enrollment windows.Enrollment }
	if code := c.do("POST", "/v1/devices/"+id+"/enroll", map[string]any{"ttl_minutes": 60}, &en); code != 200 || en.Enrollment.Code == "" ||
		!strings.Contains(en.Enrollment.Link, "servername=https%3A%2F%2Fmdm.example") {
		t.Fatal(code, en)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "reboot"}, nil); code != 409 {
		t.Fatal("command before enroll:", code)
	}

	// 登録が済んだことにする。
	if err := store.PutManaged(ctx, core.Managed{DeviceID: id, Provider: windows.Provider, State: core.ManagedActive, CertFingerprints: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "lock"}, nil); code != 400 {
		t.Fatal("lock on windows:", code)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "wipe"}, nil); code != 400 {
		t.Fatal("wipe without confirm:", code)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/commands", map[string]any{"type": "wipe", "confirm_wipe": true}, nil); code != 202 {
		t.Fatal(code)
	}
	var cmds struct{ Commands []map[string]any }
	if c.do("GET", "/v1/devices/"+id+"/commands", nil, &cmds); len(cmds.Commands) != 1 || cmds.Commands[0]["purpose"] != "wipe" {
		t.Fatal(cmds)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{}, nil); code != 202 {
		t.Fatal(code)
	}
	if code := c.do("DELETE", "/v1/devices/"+id, nil, nil); code != 409 {
		t.Fatal("delete while unenrolling:", code)
	}
	if code := c.do("POST", "/v1/devices/"+id+"/unenroll", map[string]any{"force": true}, nil); code != 204 {
		t.Fatal(code)
	}
	if code := c.do("DELETE", "/v1/devices/"+id, nil, nil); code != 204 {
		t.Fatal(code)
	}
}
