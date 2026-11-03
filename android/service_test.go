package android_test

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/android/androidtest"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
)

type env struct {
	svc   *android.Service
	fake  *androidtest.Fake
	store core.Store
	clock *testkit.Clock
}

func newEnv(t *testing.T) env {
	t.Helper()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	fake, client := androidtest.New(t)
	svc := &android.Service{
		Store: store, Client: client, Engine: &filter.Engine{Store: store, Clock: clock}, Clock: clock,
		ProjectID: "proj", CallbackURL: "https://mdm.example/android/signup/callback", DoTDomain: "dns.example",
	}
	return env{svc, fake, store, clock}
}

func (e env) signup(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.svc.StartSignup(ctx, testkit.OrgID, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.FinishSignup(ctx, e.state(t), androidtest.EnterpriseToken); err != nil {
		t.Fatal(err)
	}
}

func (e env) state(t *testing.T) string {
	u, err := url.Parse(e.fake.CallbackURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestSignup(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, err := e.svc.StartSignup(ctx, testkit.OrgID, "")
	if err != nil || !strings.HasPrefix(u, "https://") {
		t.Fatal(u, err)
	}
	if !strings.HasPrefix(e.fake.CallbackURL, "https://mdm.example/android/signup/callback?state=") {
		t.Fatal(e.fake.CallbackURL)
	}
	state := e.state(t)
	if _, err := e.svc.FinishSignup(ctx, state, "wrong"); err == nil {
		t.Fatal("bad enterprise token accepted")
	}
	// 失敗しても申し込みは使い切る（やり直しは最初から）。
	if _, err := e.svc.FinishSignup(ctx, state, androidtest.EnterpriseToken); !errors.Is(err, android.ErrBadSignup) {
		t.Fatal("state reused:", err)
	}

	if _, err := e.svc.StartSignup(ctx, testkit.OrgID, ""); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(61 * time.Minute)
	if _, err := e.svc.FinishSignup(ctx, e.state(t), androidtest.EnterpriseToken); !errors.Is(err, android.ErrBadSignup) {
		t.Fatal("expired state accepted:", err)
	}

	if _, err := e.svc.StartSignup(ctx, testkit.OrgID, ""); err != nil {
		t.Fatal(err)
	}
	ent, err := e.svc.FinishSignup(ctx, e.state(t), androidtest.EnterpriseToken)
	if err != nil || ent.Name != "enterprises/LC0test" || ent.OrgID != testkit.OrgID {
		t.Fatal(ent, err)
	}
	if _, err := e.svc.StartSignup(ctx, testkit.OrgID, ""); !errors.Is(err, core.ErrConflict) {
		t.Fatal("second enterprise:", err)
	}
	if _, err := e.svc.FinishSignup(ctx, "not-a-state", androidtest.EnterpriseToken); !errors.Is(err, android.ErrBadSignup) {
		t.Fatal(err)
	}
}

func TestEnrollPushSyncUnenroll(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pol := core.Policy{ID: "kid", OrgID: testkit.OrgID, Name: "子ども", Mode: core.FilterBlocklist,
		Device:      core.DeviceRules{FactoryResetDisabled: true, VPNConfigDisabled: true, PasscodeMinLength: 4},
		AndroidApps: core.AppRules{Mode: core.AppsOpen, Required: []string{"com.example.school"}, Blocked: []string{"com.example.game"}}}
	if err := e.store.CreatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	d := core.Device{ID: "dev_a", OrgID: testkit.OrgID, Name: "タブレット", Platform: core.PlatformAndroid, PolicyID: "kid", FilterTokenHash: h1, DoTLabelHash: h2}
	if err := e.store.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}

	if _, err := e.svc.Enroll(ctx, d, "label1", android.EnrollOptions{}); !errors.Is(err, android.ErrNoEnterprise) {
		t.Fatal("enroll before signup:", err)
	}
	e.signup(t)

	en, err := e.svc.Enroll(ctx, d, "label1", android.EnrollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if en.Mode != android.ModeFullyManaged || !en.FilterEnforced || en.URL != "" || !strings.Contains(en.QRCode, en.Token) {
		t.Fatalf("%+v", en)
	}
	name := "enterprises/LC0test/policies/dev_a"
	p := e.fake.Policy(name)
	dns := p["deviceConnectivityManagement"].(map[string]any)["privateDnsSettings"].(map[string]any)
	if dns["privateDnsHost"] != "label1.dns.example" || dns["privateDnsMode"] != "PRIVATE_DNS_SPECIFIED_HOST" {
		t.Fatal(dns)
	}
	if p["factoryResetDisabled"] != true || p["vpnConfigDisabled"] != true || p["playStoreMode"] != "BLACKLIST" {
		t.Fatal(p)
	}
	tok := e.fake.Tokens[0]
	if tok.PolicyName != name || !tok.OneTimeOnly || tok.AdditionalData != "dev_a" || tok.AllowPersonalUsage != "PERSONAL_USAGE_DISALLOWED" || tok.Duration != "3600s" {
		t.Fatalf("%+v", tok)
	}
	m, err := e.store.GetManaged(ctx, "dev_a")
	if err != nil || m.State != core.ManagedPending || m.PolicyName != name {
		t.Fatal(m, err)
	}

	// 変わっていなければ配らない。
	patches := e.fake.Patches
	if err := e.svc.PushAll(ctx); err != nil || e.fake.Patches != patches {
		t.Fatal(err, e.fake.Patches)
	}
	// ポリシーを変えると、通信フィルターのホスト名を残したまま配り直す。
	pol.AndroidApps.Mode = core.AppsAllowlist
	pol.AndroidApps.Allowed = []string{"com.example.reader"}
	pol.Device.CameraDisabled = true
	if err := e.store.UpdatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PushAll(ctx); err != nil || e.fake.Patches != patches+1 {
		t.Fatal(err, e.fake.Patches)
	}
	p = e.fake.Policy(name)
	if p["playStoreMode"] != "WHITELIST" || p["cameraAccess"] != "CAMERA_ACCESS_DISABLED" {
		t.Fatal(p)
	}
	apps := p["applications"].([]any)
	if len(apps) != 2 { // 許可の一覧のときは、禁止の一覧は書かない
		t.Fatal(apps)
	}
	if p["deviceConnectivityManagement"].(map[string]any)["privateDnsSettings"].(map[string]any)["privateDnsHost"] != "label1.dns.example" {
		t.Fatal("dns host lost", p)
	}
	for _, f := range e.fake.Masks[name] {
		if strings.HasPrefix(f, "deviceConnectivityManagement") {
			t.Fatal("push touched dns", e.fake.Masks[name])
		}
	}

	// 端末が登録されると、状態を取り込む。
	dev := android.Device{Name: "enterprises/LC0test/devices/D1", State: "ACTIVE", ManagementMode: "DEVICE_OWNER", PolicyName: name,
		PolicyCompliant: false, EnrollmentTime: "2026-11-03T03:10:00Z", LastStatusReport: "2026-11-03T03:20:00.5Z", EnrollmentTokenData: "dev_a"}
	dev.HardwareInfo.Manufacturer, dev.HardwareInfo.Model = "Google", "Pixel 9"
	dev.SoftwareInfo.AndroidVersion, dev.SoftwareInfo.SecurityPatchLevel = "16", "2026-10-05"
	dev.DeviceSettings.IsEncrypted, dev.DeviceSettings.IsDeviceSecure = true, true
	dev.NonComplianceDetails = append(dev.NonComplianceDetails, struct {
		SettingName         string `json:"settingName"`
		NonComplianceReason string `json:"nonComplianceReason"`
		PackageName         string `json:"packageName"`
	}{"applications", "APP_NOT_INSTALLED", "com.example.school"})
	stale := dev
	stale.Name, stale.State, stale.EnrollmentTime = "enterprises/LC0test/devices/D0", "DELETED", "2026-11-03T03:30:00Z"
	e.fake.SetDevices(dev, stale)
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	m, _ = e.store.GetManaged(ctx, "dev_a")
	want := core.Managed{DeviceID: "dev_a", Provider: "android", ExternalID: dev.Name, PolicyName: name, State: core.ManagedActive,
		Mode: android.ModeFullyManaged, Model: "Google Pixel 9", OSVersion: "16", SecurityPatch: "2026-10-05",
		Problems: []string{"applications: APP_NOT_INSTALLED (com.example.school)"}, Encrypted: true, ScreenLock: true,
		PolicyHash: m.PolicyHash, EnrolledAt: time.Date(2026, 11, 3, 3, 10, 0, 0, time.UTC), ReportedAt: time.Date(2026, 11, 3, 3, 20, 0, 5e8, time.UTC)}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got  %+v\nwant %+v", m, want)
	}
	got, _ := e.store.GetDevice(ctx, "dev_a")
	if !got.LastSeenAt.Equal(want.ReportedAt) {
		t.Fatal(got.LastSeenAt)
	}
	if _, err := e.svc.Enroll(ctx, d, "label2", android.EnrollOptions{}); !errors.Is(err, core.ErrConflict) {
		t.Fatal("enroll twice:", err)
	}

	if err := e.svc.Command(ctx, d, android.CommandLock); err != nil || e.fake.Commands[0] != dev.Name+" LOCK" {
		t.Fatal(err, e.fake.Commands)
	}
	if err := e.svc.Command(ctx, d, "wipe"); err == nil {
		t.Fatal("unknown command accepted")
	}

	// DoT のラベルを作り直したら、ホスト名だけを配る。
	if err := e.svc.SetFilterHost(ctx, d, "label3"); err != nil {
		t.Fatal(err)
	}
	if e.fake.Policy(name)["deviceConnectivityManagement"].(map[string]any)["privateDnsSettings"].(map[string]any)["privateDnsHost"] != "label3.dns.example" {
		t.Fatal(e.fake.Policy(name))
	}

	if err := e.svc.Unenroll(ctx, d, "返却"); err != nil {
		t.Fatal(err)
	}
	if e.fake.Policy(name) != nil || len(e.fake.Deleted) != 2 {
		t.Fatal(e.fake.Deleted)
	}
	if _, err := e.store.GetManaged(ctx, "dev_a"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal(err)
	}
	if err := e.svc.Command(ctx, d, android.CommandLock); !errors.Is(err, android.ErrNotManaged) {
		t.Fatal(err)
	}
}

func TestSyncRemoved(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.signup(t)
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	d := core.Device{ID: "dev_b", OrgID: testkit.OrgID, Name: "私物", Platform: core.PlatformAndroid, FilterTokenHash: h1, DoTLabelHash: h2}
	if err := e.store.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	en, err := e.svc.Enroll(ctx, d, "l", android.EnrollOptions{Mode: android.ModeWorkProfile, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if en.FilterEnforced || en.URL != "https://enterprise.google.com/android/enroll?et="+en.Token || e.fake.Tokens[0].AllowPersonalUsage != "PERSONAL_USAGE_ALLOWED" {
		t.Fatalf("%+v %+v", en, e.fake.Tokens[0])
	}
	// 登録を待っている間は、端末が無くても待ち続ける。
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.store.GetManaged(ctx, "dev_b"); m.State != core.ManagedPending {
		t.Fatal(m.State)
	}
	name := "enterprises/LC0test/policies/dev_b"
	e.fake.SetDevices(android.Device{Name: "enterprises/LC0test/devices/W", State: "ACTIVE", ManagementMode: "PROFILE_OWNER", PolicyName: name})
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.store.GetManaged(ctx, "dev_b"); m.State != core.ManagedActive || m.Mode != android.ModeWorkProfile {
		t.Fatal(m)
	}
	// 仕事用プロファイルを消されると、端末は AMAPI から消える。
	e.fake.SetDevices()
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.store.GetManaged(ctx, "dev_b"); m.State != core.ManagedRemoved {
		t.Fatal(m.State)
	}
	// 外れた端末は登録し直せる。
	if _, err := e.svc.Enroll(ctx, d, "l2", android.EnrollOptions{Mode: android.ModeWorkProfile}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildPolicy(t *testing.T) {
	body, mask := android.BuildPolicy(core.Policy{}, "")
	if body["playStoreMode"] != "BLACKLIST" || body["cameraAccess"] != "CAMERA_ACCESS_USER_CHOICE" || len(body["passwordPolicies"].([]map[string]any)) != 0 {
		t.Fatal(body)
	}
	if _, ok := body["deviceConnectivityManagement"]; ok {
		t.Fatal("dns without host")
	}
	for _, f := range mask {
		if _, ok := body[f]; !ok {
			t.Fatalf("mask %q not in body", f)
		}
	}
	body, mask = android.BuildPolicy(core.Policy{Device: core.DeviceRules{PasscodeMinLength: 6}}, "x.dns.example")
	pw := body["passwordPolicies"].([]map[string]any)
	if len(pw) != 1 || pw[0]["passwordMinimumLength"] != 6 || mask[len(mask)-1] != "deviceConnectivityManagement.privateDnsSettings" {
		t.Fatal(pw, mask)
	}
}
