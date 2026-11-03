package compliance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/ssf"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	d := core.Device{Platform: core.PlatformIOS}
	r := core.ComplianceRules{RequireEncryption: true, RequireScreenLock: true, MaxReportAgeHours: 24,
		MinOSVersion: map[core.Platform]string{core.PlatformIOS: "18.2"}}
	if got := compliance.Evaluate(r, d, nil, now); len(got) != 1 || got[0] != compliance.ReasonNotManaged {
		t.Fatal(got)
	}
	m := &core.Managed{State: core.ManagedActive, PolicyCompliant: true, Encrypted: true, ScreenLock: true, OSVersion: "18.2.1", ReportedAt: now.Add(-time.Hour)}
	if got := compliance.Evaluate(r, d, m, now); len(got) != 0 {
		t.Fatal(got)
	}
	m2 := *m
	m2.Encrypted, m2.ScreenLock, m2.OSVersion, m2.ReportedAt, m2.PolicyCompliant = false, false, "17.7", now.Add(-48*time.Hour), false
	got := compliance.Evaluate(r, d, &m2, now)
	if strings.Join(got, ",") != "policy_not_applied,not_encrypted,no_screen_lock,os_outdated,not_reporting" {
		t.Fatal(got)
	}
	// 機種が違えば最低の版は見ない。
	if got := compliance.Evaluate(r, core.Device{Platform: core.PlatformAndroid}, &core.Managed{State: core.ManagedActive, PolicyCompliant: true,
		Encrypted: true, ScreenLock: true, ReportedAt: now}, now); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"18.2", "18.2.0", 0}, {"18.10", "18.9", 1}, {"10.0.22631.4460", "10.0.26100", -1}, {"", "1", -1}, {"14", "13", 1}, {"14 (Build 1)", "14", 0}} {
		if got := compliance.CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%q vs %q = %d", c.a, c.b, got)
		}
	}
	if !compliance.ValidVersion("17.4") || compliance.ValidVersion("17.x") || compliance.ValidVersion("") || compliance.ValidVersion("1..2") {
		t.Fatal("ValidVersion")
	}
}

type receiver struct {
	mu   sync.Mutex
	sets []string
	code int
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.Header.Get("Authorization") != "Bearer ssfpt_x" || req.Header.Get("Content-Type") != "application/secevent+jwt" {
		w.WriteHeader(401)
		return
	}
	b, _ := io.ReadAll(req.Body)
	r.sets = append(r.sets, string(b))
	if r.code != 0 {
		w.WriteHeader(r.code)
		return
	}
	w.WriteHeader(202)
}

// verify は SET の署名を確かめて claims を返す。
func verify(t *testing.T, signer *ssf.Signer, set string) map[string]any {
	t.Helper()
	parts := strings.Split(set, ".")
	var h map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &h)
	if h["alg"] != "ES256" || h["typ"] != "secevent+jwt" || h["kid"] != signer.KID {
		t.Fatal(h)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(signer.Public().(*ecdsa.PublicKey), sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("bad signature")
	}
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &c)
	return c
}

func TestServiceNotifiesIAM(t *testing.T) {
	ctx := context.Background()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	if err := store.CreatePolicy(ctx, core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist,
		Compliance: core.ComplianceRules{RequireEncryption: true}}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePerson(ctx, core.Person{ID: "p1", OrgID: testkit.OrgID, Name: "社員", Role: core.RoleAdult, Email: "worker@example.com"}); err != nil {
		t.Fatal(err)
	}
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	d := core.Device{ID: "dev1", OrgID: testkit.OrgID, Name: "PC", Platform: core.PlatformWindows, PersonID: "p1", FilterTokenHash: h1, DoTLabelHash: h2}
	if err := store.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	signer, err := ssf.LoadOrCreateSigner(filepath.Join(t.TempDir(), "ssf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rcv := &receiver{}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	tr := &ssf.Transmitter{Store: store, Clock: clock, Signer: signer, Issuer: "https://mdm.example",
		Receivers: []ssf.Receiver{{Name: "iam", URL: srv.URL, PushToken: "ssfpt_x", Audience: "https://iam.example"}}}
	svc := &compliance.Service{Store: store, Engine: &filter.Engine{Store: store, Clock: clock}, Clock: clock, Transmitter: tr}

	// 管理していない端末は準拠していない。
	if err := svc.EvaluateAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tr.DeliverDue(ctx); err != nil || len(rcv.sets) != 1 {
		t.Fatal(err, len(rcv.sets))
	}
	c := verify(t, signer, rcv.sets[0])
	ev := c["events"].(map[string]any)[ssf.EventDeviceComplianceChange].(map[string]any)
	sub := c["sub_id"].(map[string]any)
	if c["iss"] != "https://mdm.example" || c["aud"] != "https://iam.example" || ev["current_status"] != "not-compliant" || ev["previous_status"] != nil ||
		sub["format"] != "complex" || sub["user"].(map[string]any)["email"] != "worker@example.com" || sub["device"].(map[string]any)["id"] != "dev1" {
		t.Fatal(c)
	}
	if cs, _ := store.GetCompliance(ctx, "dev1"); cs.Compliant || cs.Reasons[0] != compliance.ReasonNotManaged {
		t.Fatalf("%+v", cs)
	}

	// 変わらなければ知らせない。
	clock.Advance(time.Minute)
	_ = svc.EvaluateAll(ctx)
	_ = tr.DeliverDue(ctx)
	if len(rcv.sets) != 1 {
		t.Fatal("sent without change")
	}

	// 管理して、暗号化していれば準拠。受け手が落ちていれば送り直す。
	if err := store.PutManaged(ctx, core.Managed{DeviceID: "dev1", Provider: "windows", State: core.ManagedActive, PolicyCompliant: true, Encrypted: true}); err != nil {
		t.Fatal(err)
	}
	rcv.code = 503
	clock.Advance(time.Minute)
	_ = svc.EvaluateAll(ctx)
	_ = tr.DeliverDue(ctx)
	if len(rcv.sets) != 2 {
		t.Fatal(len(rcv.sets))
	}
	rcv.code = 0
	_ = tr.DeliverDue(ctx) // まだ送り直す時刻ではない
	if len(rcv.sets) != 2 {
		t.Fatal("retried too early")
	}
	clock.Advance(11 * time.Second)
	_ = tr.DeliverDue(ctx)
	if len(rcv.sets) != 3 {
		t.Fatal(len(rcv.sets))
	}
	c = verify(t, signer, rcv.sets[2])
	ev = c["events"].(map[string]any)[ssf.EventDeviceComplianceChange].(map[string]any)
	if ev["current_status"] != "compliant" || ev["previous_status"] != "not-compliant" {
		t.Fatal(ev)
	}
	if due, _ := store.DueSSF(ctx, clock.Now().Add(time.Hour), 10); len(due) != 0 {
		t.Fatal(due)
	}

	// 受け手が 400 で断ったものは送り直さない。
	rcv.code = 400
	if err := store.PutManaged(ctx, core.Managed{DeviceID: "dev1", Provider: "windows", State: core.ManagedActive, PolicyCompliant: true}); err != nil {
		t.Fatal(err)
	}
	_ = svc.EvaluateAll(ctx)
	_ = tr.DeliverDue(ctx)
	if due, _ := store.DueSSF(ctx, clock.Now().Add(2*time.Hour), 10); len(due) != 0 {
		t.Fatal(due)
	}
}

func TestSignerReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssf.pem")
	a, err := ssf.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ssf.LoadOrCreateSigner(path)
	if err != nil || a.KID != b.KID {
		t.Fatal(err)
	}
	var jwks struct{ Keys []map[string]string }
	if err := json.Unmarshal(a.JWKS(), &jwks); err != nil || jwks.Keys[0]["kid"] != a.KID || jwks.Keys[0]["crv"] != "P-256" {
		t.Fatal(jwks)
	}
}
