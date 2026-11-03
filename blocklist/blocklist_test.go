package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestParse(t *testing.T) {
	in := `# hosts 形式
0.0.0.0 ads.example
127.0.0.1 Tracker.Example # 後ろのコメント
0.0.0.0 localhost
192.168.0.1 router.example
plain.example
||adblock.example^
||path.example/ads^
! Adblock のコメント
ads.example
not a domain at all
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example", "tracker.example", "plain.example", "adblock.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestValidateURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://example.com/list.txt":     true,
		"http://example.com/list.txt":      false,
		"https://user:pw@example.com/list": false,
		"file:///etc/hosts":                false,
	} {
		if err := ValidateURL(raw); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestRefreshKeepsOldOnError(t *testing.T) {
	ctx := context.Background()
	fail := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "x", 500)
			return
		}
		_, _ = w.Write([]byte("a.example\n"))
	}))
	defer srv.Close()
	store := testkit.Store(t)
	changed := 0
	r := &Refresher{Store: store, Clock: testkit.NewClock(time.Unix(0, 0)), Client: srv.Client(), OnChange: func() { changed++ }}
	if err := store.CreateBlocklist(ctx, core.Blocklist{ID: "bl", Name: "x", URL: srv.URL + "/l"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(ctx, "bl"); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := r.Refresh(ctx, "bl"); err == nil {
		t.Fatal("失敗を返すべき")
	}
	ds, _ := store.BlocklistDomains(ctx, "bl")
	b, _ := store.GetBlocklist(ctx, "bl")
	if len(ds) != 1 || b.LastError == "" || changed != 1 {
		t.Fatalf("前の中身を残す: %v %+v %d", ds, b, changed)
	}
}
