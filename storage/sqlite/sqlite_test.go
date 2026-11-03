package sqlite_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := testkit.Store(t)
	now := time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC)

	pol := core.Policy{ID: "pol1", Name: "子ども", Mode: core.FilterAllowlistOnly, Allow: []string{"a.example"},
		Quiet: []core.Window{{Days: []time.Weekday{time.Monday}, Start: 60, End: 120}}, TimeZone: "Asia/Tokyo", LogQueries: true, UpdatedAt: now}
	if err := s.CreatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPolicy(ctx, "pol1")
	if err != nil || !reflect.DeepEqual(got, pol) {
		t.Fatalf("policy: %+v %v", got, err)
	}

	per := core.Person{ID: "per1", Name: "はなこ", Role: core.RoleChild, PolicyID: "pol1", CreatedAt: now}
	if err := s.CreatePerson(ctx, per); err != nil {
		t.Fatal(err)
	}
	dev := core.Device{ID: "dev1", Name: "iPhone", Platform: core.PlatformIOS, PersonID: "per1", FilterTokenHash: []byte{1, 2, 3}, CreatedAt: now}
	if err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	gd, err := s.GetDeviceByTokenHash(ctx, []byte{1, 2, 3})
	if err != nil || !reflect.DeepEqual(gd, dev) {
		t.Fatalf("device: %+v %v", gd, err)
	}

	// 参照されているものは消せない。
	if err := s.DeletePerson(ctx, "per1"); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("delete person in use: %v", err)
	}
	if err := s.DeletePolicy(ctx, "pol1"); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("delete policy in use: %v", err)
	}
	// 無いポリシーは指せない。
	dev.PolicyID = "nope"
	if err := s.UpdateDevice(ctx, dev); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("missing policy: %v", err)
	}
	if err := s.DeleteDevice(ctx, "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}

	// 最後の通信の時刻は進むだけ。
	_ = s.TouchDevice(ctx, "dev1", now.Add(time.Hour))
	_ = s.TouchDevice(ctx, "dev1", now)
	gd, _ = s.GetDevice(ctx, "dev1")
	if !gd.LastSeenAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("last seen: %v", gd.LastSeenAt)
	}
}

func TestBlocklistAndLogs(t *testing.T) {
	ctx := context.Background()
	s := testkit.Store(t)
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	if err := s.CreateBlocklist(ctx, core.Blocklist{ID: "bl", Name: "ads", URL: "https://x/list"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBlocklistDomains(ctx, "bl", []string{"a.example", "b.example", "a.example"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBlocklistDomains(ctx, "bl", []string{"c.example"}, now); err != nil {
		t.Fatal(err)
	}
	ds, _ := s.BlocklistDomains(ctx, "bl")
	if !reflect.DeepEqual(ds, []string{"c.example"}) {
		t.Fatalf("入れ替え: %v", ds)
	}
	b, _ := s.GetBlocklist(ctx, "bl")
	if b.Domains != 1 || !b.RefreshedAt.Equal(now) {
		t.Fatalf("blocklist: %+v", b)
	}
	if err := s.DeleteBlocklist(ctx, "bl"); err != nil {
		t.Fatal(err)
	}
	if ds, _ := s.BlocklistDomains(ctx, "bl"); len(ds) != 0 {
		t.Fatal("一覧を消したら中身も消える")
	}

	logs := []core.QueryLog{
		{DeviceID: "d", At: now, Name: "old.example", Type: "A", Action: core.ActionBlock, Reason: "blocked"},
		{DeviceID: "d", At: now.Add(time.Hour), Name: "new.example", Type: "AAAA", Action: core.ActionAllow, Reason: "default"},
	}
	if err := s.AppendQueryLogs(ctx, logs); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListQueryLogs(ctx, "d", time.Time{}, 10)
	if len(got) != 2 || got[0].Name != "new.example" {
		t.Fatalf("新しい順: %+v", got)
	}
	n, _ := s.DeleteQueryLogsBefore(ctx, now.Add(time.Minute))
	if n != 1 {
		t.Fatalf("retention: %d", n)
	}
}
