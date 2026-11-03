package ssf

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/internal/testkit"
)

// 組織を決めた受け手には、その組織の端末の知らせだけを送る。
func TestEnqueueByOrg(t *testing.T) {
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	signer, err := LoadOrCreateSigner(filepath.Join(t.TempDir(), "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tr := &Transmitter{Store: store, Clock: clock, Signer: signer, Issuer: "https://mdm.example", Receivers: []Receiver{
		{Name: "all", URL: "https://all.example", PushToken: "t", Audience: "a"},
		{Name: "a", URL: "https://a.example", PushToken: "t", Audience: "a", OrgIDs: []string{"org_a"}},
		{Name: "b", URL: "https://b.example", PushToken: "t", Audience: "b", OrgIDs: []string{"org_b"}},
	}}
	ctx := context.Background()
	if err := tr.Enqueue(ctx, ComplianceChange{Email: "x@example.com", DeviceID: "dev1", OrgID: "org_a", Current: StatusCompliant, ChangedAt: clock.Now()}); err != nil {
		t.Fatal(err)
	}
	evs, err := store.DueSSF(ctx, clock.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range evs {
		got[e.Receiver] = true
	}
	if len(evs) != 2 || !got["all"] || !got["a"] {
		t.Fatal(got)
	}
}
