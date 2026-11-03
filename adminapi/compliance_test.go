package adminapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/ssf"
)

func TestComplianceAPI(t *testing.T) {
	var got atomic.Int32
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Add(1); w.WriteHeader(202) }))
	defer rcv.Close()
	signer, err := ssf.LoadOrCreateSigner(filepath.Join(t.TempDir(), "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var svc *compliance.Service
	var tr *ssf.Transmitter
	c, _, _ := newServer(t, func(s *adminapi.Server) {
		tr = &ssf.Transmitter{Store: s.Store, Clock: s.Clock, Signer: signer, Issuer: "https://mdm.example",
			Receivers: []ssf.Receiver{{Name: "iam", URL: rcv.URL, PushToken: "t", Audience: "a"}}}
		svc = &compliance.Service{Store: s.Store, Engine: s.Engine, Clock: s.Clock, Transmitter: tr}
		s.Compliance = svc
	})
	ctx := context.Background()

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "会社",
		"compliance": map[string]any{"require_encryption": true, "min_os_version": map[string]string{"ios": "18.2", "windows": "10.0.22631"}}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if cp := pol["compliance"].(map[string]any); cp["require_encryption"] != true || cp["min_os_version"].(map[string]any)["ios"] != "18.2" {
		t.Fatal(pol)
	}
	for _, bad := range []map[string]any{{"min_os_version": map[string]string{"ios": "x"}}, {"min_os_version": map[string]string{"other": "1"}}, {"max_report_age_hours": -1}} {
		if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "compliance": bad}, nil); code != 400 {
			t.Fatal(bad, code)
		}
	}

	var person map[string]any
	if code := c.do("POST", "/v1/people", map[string]any{"org_id": testkit.OrgID, "name": "社員", "role": "adult"}, &person); code != 201 {
		t.Fatal(code, person)
	}
	pid := person["id"].(string)
	if code := c.do("PATCH", "/v1/people/"+pid, map[string]any{"email": "not-an-email"}, nil); code != 400 {
		t.Fatal(code)
	}
	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "PC", "platform": "windows", "person_id": pid}, &dev)
	id := dev.Device["id"].(string)
	if err := svc.EvaluateAll(ctx); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	c.do("GET", "/v1/devices/"+id, nil, &out)
	if cp := out["compliance"].(map[string]any); cp["compliant"] != false || cp["reasons"].([]any)[0] != compliance.ReasonNotManaged {
		t.Fatal(out)
	}
	// メールアドレスが無いうちは知らせない。付けたら今の状態を知らせる。
	_ = tr.DeliverDue(ctx)
	if got.Load() != 0 {
		t.Fatal(got.Load())
	}
	if code := c.do("PATCH", "/v1/people/"+pid, map[string]any{"email": " Worker@Example.com "}, &person); code != 200 || person["email"] != "worker@example.com" {
		t.Fatal(code, person)
	}
	_ = tr.DeliverDue(ctx)
	if got.Load() != 1 {
		t.Fatal(got.Load())
	}
}
