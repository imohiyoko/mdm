package filter_test

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestDomainSet(t *testing.T) {
	s := filter.NewDomainSet([]string{"Example.COM.", "bad domain", "ads.test"})
	for name, want := range map[string]bool{
		"example.com":      true,
		"www.example.com":  true,
		"notexample.com":   false,
		"ads.test":         true,
		"x.ads.test":       true,
		"test":             false,
		"example.com.evil": false,
	} {
		if _, got := s.Match(name); got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	if len(s) != 2 {
		t.Errorf("使えないドメインは捨てる: %v", s)
	}
}

type fixture struct {
	ctx    context.Context
	store  core.Store
	clock  *testkit.Clock
	engine *filter.Engine
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	store := testkit.Store(t)
	// 2026-11-02 月曜 12:00 JST
	clock := testkit.NewClock(time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC))
	f := &fixture{ctx, store, clock, &filter.Engine{Store: store, Clock: clock, AlwaysAllow: filter.NewDomainSet([]string{"push.apple.com"})}}
	f.must(store.CreatePolicy(ctx, core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}))
	return f
}

func (f *fixture) must(err error) {
	if err != nil {
		panic(err)
	}
}

func (f *fixture) device(id, person, policy string) core.Device {
	_, hash := core.NewFilterToken()
	_, labelHash := core.NewFilterToken()
	d := core.Device{OrgID: testkit.OrgID, ID: id, Name: id, Platform: core.PlatformAndroid, PersonID: person, PolicyID: policy, FilterTokenHash: hash, DoTLabelHash: labelHash}
	f.must(f.store.CreateDevice(f.ctx, d))
	f.must(f.engine.Refresh(f.ctx))
	return d
}

func (f *fixture) decide(t *testing.T, d core.Device, name string) filter.Decision {
	t.Helper()
	dec, _, err := f.engine.Decide(f.ctx, d, name)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

func TestDecideOrder(t *testing.T) {
	f := setup(t)
	f.must(f.store.CreateBlocklist(f.ctx, core.Blocklist{ID: "bl1", Name: "ads", URL: "https://x"}))
	f.must(f.store.ReplaceBlocklistDomains(f.ctx, "bl1", []string{"ads.example"}, f.clock.Now()))
	f.must(f.store.CreatePolicy(f.ctx, core.Policy{
		ID: "kids", Name: "子ども", Mode: core.FilterBlocklist,
		Allow: []string{"school.example", "ok.ads.example"}, Block: []string{"game.example"}, ListIDs: []string{"bl1"},
		Quiet: []core.Window{{Start: 21 * 60, End: 7 * 60}}, TimeZone: "Asia/Tokyo",
	}))
	f.must(f.store.CreatePerson(f.ctx, core.Person{OrgID: testkit.OrgID, ID: "p1", Name: "たろう", Role: core.RoleChild, PolicyID: "kids"}))
	d := f.device("d1", "p1", "")

	cases := []struct {
		name   string
		action core.Action
		reason filter.Reason
	}{
		{"www.game.example", core.ActionBlock, filter.ReasonBlocked},
		{"tracker.ads.example", core.ActionBlock, filter.ReasonBlocklist},
		{"ok.ads.example", core.ActionAllow, filter.ReasonAllowed},
		{"news.example", core.ActionAllow, filter.ReasonDefault},
		{"PUSH.apple.com.", core.ActionAllow, filter.ReasonAlwaysAllowed},
	}
	for _, c := range cases {
		dec := f.decide(t, d, c.name)
		if dec.Action != c.action || dec.Reason != c.reason {
			t.Errorf("%s: got %+v", c.name, dec)
		}
	}

	// 22:00 JST は止める時間帯。許可の一覧といつも許す通信だけ通る。
	f.clock.Set(time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC))
	if dec := f.decide(t, d, "news.example"); dec.Reason != filter.ReasonQuietHours {
		t.Errorf("夜: %+v", dec)
	}
	if dec := f.decide(t, d, "school.example"); dec.Action != core.ActionAllow {
		t.Errorf("夜でも許可の一覧は通す: %+v", dec)
	}
	if dec := f.decide(t, d, "push.apple.com"); dec.Action != core.ActionAllow {
		t.Errorf("夜でも端末の管理は通す: %+v", dec)
	}
}

func TestPauseAndAllowlistOnly(t *testing.T) {
	f := setup(t)
	f.must(f.store.CreatePolicy(f.ctx, core.Policy{ID: "small", Name: "小さい子", Mode: core.FilterAllowlistOnly, Allow: []string{"kids.example"}}))
	d := f.device("d1", "", "small")
	if dec := f.decide(t, d, "kids.example"); dec.Action != core.ActionAllow {
		t.Errorf("許可: %+v", dec)
	}
	if dec := f.decide(t, d, "other.example"); dec.Reason != filter.ReasonNotAllowed {
		t.Errorf("一覧に無い: %+v", dec)
	}

	d2 := f.device("d2", "", "")
	d2.PausedUntil = f.clock.Now().Add(30 * time.Minute)
	if dec := f.decide(t, d2, "news.example"); dec.Reason != filter.ReasonPaused {
		t.Errorf("止めている: %+v", dec)
	}
	f.clock.Advance(31 * time.Minute)
	if dec := f.decide(t, d2, "news.example"); dec.Action != core.ActionAllow {
		t.Errorf("時間が過ぎたら戻る: %+v", dec)
	}
}

func TestPolicyFallback(t *testing.T) {
	f := setup(t)
	f.must(f.store.CreatePolicy(f.ctx, core.Policy{ID: "person", Name: "人", Block: []string{"a.example"}}))
	f.must(f.store.CreatePolicy(f.ctx, core.Policy{ID: "device", Name: "端末", Block: []string{"b.example"}}))
	f.must(f.store.CreatePerson(f.ctx, core.Person{OrgID: testkit.OrgID, ID: "p1", Name: "x", Role: core.RoleChild, PolicyID: "person"}))
	byPerson := f.device("d1", "p1", "")
	byDevice := f.device("d2", "p1", "device")
	byDefault := f.device("d3", "", "")
	for _, c := range []struct {
		d    core.Device
		want string
	}{{byPerson, "person"}, {byDevice, "device"}, {byDefault, filter.DefaultPolicyID}} {
		p, ok, err := f.engine.PolicyFor(f.ctx, c.d)
		if err != nil || !ok || p.ID != c.want {
			t.Errorf("%s: got %q %v %v", c.d.ID, p.ID, ok, err)
		}
	}
}

func TestDeviceLookupAndInvalidate(t *testing.T) {
	f := setup(t)
	tok, hash := core.NewFilterToken()
	label, labelHash := core.NewFilterToken()
	f.must(f.store.CreateDevice(f.ctx, core.Device{OrgID: testkit.OrgID, ID: "d1", Name: "d", Platform: core.PlatformIOS, FilterTokenHash: hash, DoTLabelHash: labelHash}))
	if _, err := f.engine.Device(f.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.DeviceByDoTLabel(f.ctx, label); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.DeviceByDoTLabel(f.ctx, tok); err != core.ErrNotFound {
		t.Fatalf("DoH の秘密は DoT のラベルに使えない: %v", err)
	}
	// 秘密を作り直すと、古い秘密は読み直しのあと効かなくなる。
	_, hash2 := core.NewFilterToken()
	d, _ := f.store.GetDevice(f.ctx, "d1")
	d.FilterTokenHash = hash2
	f.must(f.store.UpdateDevice(f.ctx, d))
	f.must(f.engine.Refresh(f.ctx))
	if _, err := f.engine.Device(f.ctx, tok); err != core.ErrNotFound {
		t.Fatalf("古い秘密: %v", err)
	}
	if _, err := f.engine.Device(f.ctx, "not-a-token"); err != core.ErrNotFound {
		t.Fatalf("形の違う秘密: %v", err)
	}
}

func TestInvalidNameIsBlocked(t *testing.T) {
	f := setup(t)
	d := f.device("d1", "", "")
	if dec := f.decide(t, d, "bad name!.example"); dec.Action != core.ActionBlock || dec.Reason != filter.ReasonInvalidName {
		t.Errorf("読めない名前: %+v", dec)
	}
	if dec := f.decide(t, d, "."); dec.Action != core.ActionAllow {
		t.Errorf("ルート: %+v", dec)
	}
}

// failingStore は fail の間、端末の一覧の読み込みに失敗する。
type failingStore struct {
	core.Store
	fail bool
}

func (s *failingStore) ListDevices(ctx context.Context) ([]core.Device, error) {
	if s.fail {
		return nil, context.DeadlineExceeded
	}
	return s.Store.ListDevices(ctx)
}

func TestKeepsSnapshotWhenReloadFails(t *testing.T) {
	f := setup(t)
	tok, hash := core.NewFilterToken()
	_, labelHash := core.NewFilterToken()
	f.must(f.store.CreateDevice(f.ctx, core.Device{OrgID: testkit.OrgID, ID: "d1", Name: "d", Platform: core.PlatformIOS, FilterTokenHash: hash, DoTLabelHash: labelHash}))
	fs := &failingStore{Store: f.store}
	e := &filter.Engine{Store: fs, Clock: f.clock}
	if _, err := e.Device(f.ctx, tok); err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	if err := e.Refresh(f.ctx); err == nil {
		t.Fatal("失敗を返すべき")
	}
	// 保存先が落ちていても、前の内容で判定を続ける。
	f.clock.Advance(time.Hour)
	if _, err := e.Device(f.ctx, tok); err != nil {
		t.Fatalf("前の内容を使うべき: %v", err)
	}
}
