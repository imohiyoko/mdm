package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

type fakePusher struct {
	mu     sync.Mutex
	pushes []string
}

func (f *fakePusher) Push(_ context.Context, token []byte, magic string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushes = append(f.pushes, string(token)+"/"+magic)
	return nil
}

func (f *fakePusher) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.pushes) }

type env struct {
	svc   *Service
	store core.Store
	clock *testkit.Clock
	push  *fakePusher
	dev   core.Device
	srv   *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	ca, err := pki.NewCA("test CA", 2048)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.CreatePolicy(ctx, core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	d := core.Device{ID: "dev_i", OrgID: testkit.OrgID, Name: "iPhone", Platform: core.PlatformIOS, FilterTokenHash: h1, DoTLabelHash: h2}
	if err := store.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	push := &fakePusher{}
	svc := &Service{Store: store, Engine: &filter.Engine{Store: store, Clock: clock}, Clock: clock, CA: ca, Pusher: push,
		Topic: "com.apple.mgmt.External.test", BaseURL: "https://mdm.example", DoHBaseURL: "https://dns.example", Logger: slog.New(slog.DiscardHandler)}
	srv := httptest.NewUnstartedServer(svc.Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{svc, store, clock, push, d, srv}
}

// enroll は登録のプロファイルを取り出し、中の証明書を持ったクライアントを返す。
func (e *env) enroll(t *testing.T) *http.Client {
	t.Helper()
	en, err := e.svc.CreateEnrollment(context.Background(), e.dev, "dohsecret", time.Hour)
	if err != nil || !en.FilterEnforced {
		t.Fatal(en, err)
	}
	path := strings.TrimPrefix(en.ProfileURL, "https://mdm.example")
	resp, err := e.srv.Client().Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatal(resp.StatusCode, string(b))
	}
	var prof struct {
		PayloadContent []map[string]any
	}
	if _, err := plist.Unmarshal(b, &prof); err != nil {
		t.Fatal(err)
	}
	p12 := prof.PayloadContent[0]
	mdm := prof.PayloadContent[1]
	if mdm["PayloadType"] != "com.apple.mdm" || mdm["Topic"] != "com.apple.mgmt.External.test" || mdm["ServerURL"] != "https://mdm.example/apple/mdm" ||
		mdm["IdentityCertificateUUID"] != p12["PayloadUUID"] {
		t.Fatal(mdm)
	}
	key, cert, _, err := pkcs12.DecodeChain(p12["PayloadContent"].([]byte), p12["Password"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if id, err := e.svc.CA.Verify(cert, e.clock.Now()); err != nil || id != e.dev.ID {
		t.Fatal(id, err)
	}
	// 2 回目は取り出せない。
	if resp, _ := e.srv.Client().Get(e.srv.URL + path); resp.StatusCode != 404 {
		t.Fatal("profile downloaded twice")
	}
	tr := e.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
	return &http.Client{Transport: tr}
}

func (e *env) put(t *testing.T, c *http.Client, path string, msg map[string]any) (int, map[string]any) {
	t.Helper()
	body, _ := plist.Marshal(msg, plist.XMLFormat)
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+path, bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(b) == 0 {
		return resp.StatusCode, nil
	}
	var out map[string]any
	if _, err := plist.Unmarshal(b, &out); err != nil {
		t.Fatal(err, string(b))
	}
	return 200, out
}

func (e *env) checkIn(t *testing.T, c *http.Client) {
	t.Helper()
	if code, _ := e.put(t, c, PathCheckIn, map[string]any{"MessageType": "Authenticate", "UDID": "UDID-1", "Topic": "com.apple.mgmt.External.test", "OSVersion": "18.1", "ProductName": "iPhone17,1"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := e.put(t, c, PathCheckIn, map[string]any{"MessageType": "TokenUpdate", "UDID": "UDID-1", "Token": []byte{1, 2, 3}, "PushMagic": "magic-1"}); code != 200 {
		t.Fatal(code)
	}
}

// installed は InstallProfile の命令の中のプロファイル。
func installed(t *testing.T, cmd map[string]any) map[string]any {
	t.Helper()
	var p map[string]any
	if _, err := plist.Unmarshal(cmd["Command"].(map[string]any)["Payload"].([]byte), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func requestType(cmd map[string]any) string {
	return cmd["Command"].(map[string]any)["RequestType"].(string)
}

func TestEnrollAndManage(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if code, _ := e.put(t, e.srv.Client(), PathCheckIn, map[string]any{"MessageType": "Authenticate"}); code != 401 {
		t.Fatal("no client certificate:", code)
	}
	c := e.enroll(t)
	e.checkIn(t, c)
	m, _ := e.store.GetManaged(ctx, e.dev.ID)
	if m.State != core.ManagedActive || m.ExternalID != "UDID-1" || m.PushToken != "010203" || m.PushMagic != "magic-1" {
		t.Fatalf("%+v", m)
	}
	if err := e.svc.SyncAll(ctx); err != nil || e.push.count() != 1 {
		t.Fatal(err, e.push.count())
	}

	// 端末が来たら、命令を 1 つずつ渡す。
	_, cmd := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	if requestType(cmd) != "InstallProfile" {
		t.Fatal(cmd)
	}
	dns := installed(t, cmd)["PayloadContent"].([]any)[0].(map[string]any)
	if dns["PayloadType"] != "com.apple.dnsSettings.managed" || dns["DNSSettings"].(map[string]any)["ServerURL"] != "https://dns.example/dns-query/dohsecret" {
		t.Fatal(dns)
	}
	seen := map[string]bool{}
	for i := 0; i < 10 && cmd != nil; i++ {
		ans := map[string]any{"UDID": "UDID-1", "Status": "Acknowledged", "CommandUUID": cmd["CommandUUID"]}
		switch requestType(cmd) {
		case "DeviceInformation":
			ans["QueryResponses"] = map[string]any{"OSVersion": "18.1.1", "ModelName": "iPhone", "IsSupervised": true}
		case "SecurityInfo":
			ans["SecurityInfo"] = map[string]any{"PasscodePresent": true}
		}
		seen[requestType(cmd)] = true
		_, cmd = e.put(t, c, PathServer, ans)
	}
	if !seen["DeviceInformation"] || !seen["SecurityInfo"] {
		t.Fatal(seen)
	}
	m, _ = e.store.GetManaged(ctx, e.dev.ID)
	if m.OSVersion != "18.1.1" || !m.Supervised || m.Mode != "supervised" || !m.ScreenLock || !m.PolicyCompliant {
		t.Fatalf("%+v", m)
	}
	// DoH の秘密は送り終えたら残さない。
	cmds, _ := e.store.ListCommands(ctx, e.dev.ID, 100)
	for _, x := range cmds {
		if strings.Contains(x.Data, "dohsecret") {
			t.Fatal("doh secret kept:", x.ID)
		}
	}

	// ポリシーを変えると、通知して配る。
	pol, _ := e.store.GetPolicy(ctx, filter.DefaultPolicyID)
	pol.Device.CameraDisabled = true
	pol.AppleApps = core.AppRules{Mode: core.AppsOpen, Blocked: []string{"com.example.game"}}
	if err := e.store.UpdatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SyncAll(ctx); err != nil || e.push.count() != 2 {
		t.Fatal(err, e.push.count())
	}
	_, cmd = e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	r := installed(t, cmd)["PayloadContent"].([]any)[0].(map[string]any)
	if r["allowCamera"] != false || r["blockedAppBundleIDs"].([]any)[0] != "com.example.game" {
		t.Fatal(r)
	}
	// 端末が今はできないと答えたら、あとで送り直す。
	if _, next := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "NotNow", "CommandUUID": cmd["CommandUUID"]}); next != nil {
		t.Fatal(next)
	}
	_, again := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	if again["CommandUUID"] != cmd["CommandUUID"] {
		t.Fatal(again)
	}
	e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Error", "CommandUUID": cmd["CommandUUID"],
		"ErrorChain": []any{map[string]any{"ErrorDomain": "MCProfileErrorDomain", "ErrorCode": 4001, "LocalizedDescription": "bad"}}})
	if m, _ = e.store.GetManaged(ctx, e.dev.ID); m.PolicyCompliant || len(m.Problems) != 1 || !strings.Contains(m.Problems[0], "4001") {
		t.Fatalf("%+v", m)
	}

	// ロック。
	if err := e.svc.Command(ctx, e.dev, CommandLock); err != nil || e.push.count() != 3 {
		t.Fatal(err, e.push.count())
	}
	_, cmd = e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	if requestType(cmd) != "DeviceLock" {
		t.Fatal(cmd)
	}
	e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Acknowledged", "CommandUUID": cmd["CommandUUID"]})

	// 管理を外す。
	if err := e.svc.Unenroll(ctx, e.dev, false); err != nil {
		t.Fatal(err)
	}
	_, cmd = e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	if requestType(cmd) != "RemoveProfile" || cmd["Command"].(map[string]any)["Identifier"] != EnrollIdentifier {
		t.Fatal(cmd)
	}
	e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Acknowledged", "CommandUUID": cmd["CommandUUID"]})
	if m, _ = e.store.GetManaged(ctx, e.dev.ID); m.State != core.ManagedRemoved {
		t.Fatal(m.State)
	}
	if code, _ := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"}); code != 401 {
		t.Fatal("removed device accepted:", code)
	}
}

func TestCheckOut(t *testing.T) {
	e := newEnv(t)
	c := e.enroll(t)
	e.checkIn(t, c)
	e.put(t, c, PathCheckIn, map[string]any{"MessageType": "CheckOut", "UDID": "UDID-1"})
	m, _ := e.store.GetManaged(context.Background(), e.dev.ID)
	if m.State != core.ManagedRemoved || len(m.CertFingerprints) != 0 {
		t.Fatalf("%+v", m)
	}
	if n, _ := e.store.NextCommands(context.Background(), e.dev.ID, e.clock.Now(), 10); len(n) != 0 {
		t.Fatal(n)
	}
	// 外れた端末は登録し直せる。
	if _, err := e.svc.CreateEnrollment(context.Background(), e.dev, "", time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyProfileAllowlist(t *testing.T) {
	var p map[string]any
	plist.Unmarshal(policyProfile("d", core.Policy{AppleApps: core.AppRules{Mode: core.AppsAllowlist, Allowed: []string{"com.apple.mobilesafari"}, Blocked: []string{"x.y"}},
		Device: core.DeviceRules{PasscodeMinLength: 6}}), &p)
	pl := p["PayloadContent"].([]any)
	r := pl[0].(map[string]any)
	if _, ok := r["blockedAppBundleIDs"]; ok || r["allowListedAppBundleIDs"].([]any)[0] != "com.apple.mobilesafari" {
		t.Fatal(r)
	}
	if pc := pl[1].(map[string]any); pc["PayloadType"] != "com.apple.mobiledevice.passwordpolicy" || pc["minLength"] != uint64(6) {
		t.Fatal(pc)
	}
	// 同じ内容なら同じ形（配り直しの判定に使う）。
	if !bytes.Equal(policyProfile("d", core.Policy{}), policyProfile("d", core.Policy{})) {
		t.Fatal("not stable")
	}
}
