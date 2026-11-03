package rulescli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/API/define"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/rulescli"
)

const token = "mdm_rules_test"

func setup(t *testing.T) (core.Store, *rulescli.Client) {
	t.Helper()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	if err := store.CreatePolicy(context.Background(), core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	s := &adminapi.Server{Store: store, Clock: clock, Engine: &filter.Engine{Store: store, Clock: clock},
		Tokens: []adminapi.AdminToken{{Name: "ci", SHA256: hex.EncodeToString(sum[:]), Role: core.AdminOrg, OrgID: testkit.OrgID}}}
	api, err := s.RulesAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(api.Handler(define.Public))
	t.Cleanup(hs.Close)
	return store, &rulescli.Client{BaseURL: hs.URL, Token: token}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, c *rulescli.Client, args ...string) (int, string) {
	t.Helper()
	t.Setenv("MDM_RULES_URL", c.BaseURL)
	t.Setenv("MDM_RULES_TOKEN", c.Token)
	t.Setenv("MDM_ORG_ID", testkit.OrgID)
	var out, errb bytes.Buffer
	code := rulescli.Main(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestPlanApply(t *testing.T) {
	store, c := setup(t)
	dir := t.TempDir()
	write(t, dir, "kids.yaml", `
name: 小学生
mode: blocklist
block: [game.example, video.example]
allow: [school.example]
quiet_hours:
  - {start: 21:00, end: 07:00}
time_zone: Asia/Tokyo
`)
	// plan は作るものを見せるだけ。
	code, out := run(t, c, "plan", "-dir", dir, "-detailed-exitcode")
	if code != 2 || !strings.Contains(out, "+ 小学生（作る）") || !strings.Contains(out, "+ game.example") {
		t.Fatal(code, out)
	}
	if ps, _ := store.ListPolicies(t.Context()); len(ps) != 1 {
		t.Fatal("plan saved")
	}
	if code, out := run(t, c, "apply", "-dir", dir); code != 0 || !strings.Contains(out, "反映した: 小学生") {
		t.Fatal(code, out)
	}
	// もう一度は何も変わらない（名前でポリシーを見つける）。
	if code, out := run(t, c, "plan", "-dir", dir, "-detailed-exitcode"); code != 0 || !strings.Contains(out, "= 小学生") {
		t.Fatal(code, out)
	}
	if code, out := run(t, c, "apply", "-dir", dir); code != 0 || !strings.Contains(out, "変えるものは無い") {
		t.Fatal(code, out)
	}

	// ファイルを変えると差分が出て、apply で反映する。
	write(t, dir, "kids.yaml", `
name: 小学生
block: [game.example, sns.example]
allow: [school.example]
time_zone: Asia/Tokyo
`)
	code, out = run(t, c, "plan", "-dir", dir)
	if code != 0 || !strings.Contains(out, "~ 小学生") || !strings.Contains(out, "block: + sns.example  - video.example") || !strings.Contains(out, "quiet_hours:") {
		t.Fatal(code, out)
	}
	if code, out := run(t, c, "apply", "-dir", dir); code != 0 {
		t.Fatal(code, out)
	}
	var kids core.Policy
	ps, _ := store.ListPolicies(t.Context())
	for _, p := range ps {
		if p.Name == "小学生" {
			kids = p
		}
	}
	if len(kids.Block) != 2 || kids.Block[1] != "sns.example" || len(kids.Quiet) != 0 {
		t.Fatal(kids)
	}

	// export したファイルは、そのまま plan しても変わらない。
	exp := t.TempDir()
	if code, out := run(t, c, "export", "-dir", exp); code != 0 {
		t.Fatal(code, out)
	}
	if code, out := run(t, c, "plan", "-dir", exp, "-detailed-exitcode"); code != 0 {
		t.Fatal(code, out)
	}
	if code, _ := run(t, c, "export", "-dir", exp); code != 1 { // 上書きしない
		t.Fatal(code)
	}
}

// ファイルの書き間違いは plan で止まる。
func TestPlanErrors(t *testing.T) {
	_, c := setup(t)
	for _, tc := range []struct{ files map[string]string }{
		{map[string]string{"a.yaml": "name: a\nblok: [x.example]\n"}},         // 知らない項目
		{map[string]string{"a.yaml": "block: [x.example]\n"}},                 // 名前が無い
		{map[string]string{"a.yaml": "name: a\n", "b.yaml": "name: a\n"}},     // 同じ名前
		{map[string]string{"a.yaml": "id: pol_nope\nname: a\n"}},              // 無い id
		{map[string]string{"a.yaml": "name: a\nblock: [\"not a domain\"]\n"}}, // 確かめで落ちる
		{map[string]string{"a.yaml": "id: pol_default\nname: 既定\n"}},          // ほかの組織（サーバー全体）のもの
	} {
		dir := t.TempDir()
		for n, b := range tc.files {
			write(t, dir, n, b)
		}
		if code, out := run(t, c, "plan", "-dir", dir); code != 1 {
			t.Errorf("%v: %d %s", tc.files, code, out)
		}
	}
}

// plan のあとにほかの人が変えたら、apply は上書きしない。
func TestApplyConflict(t *testing.T) {
	store, c := setup(t)
	dir := t.TempDir()
	write(t, dir, "a.yaml", "name: a\nblock: [x.example]\n")
	if code, out := run(t, c, "apply", "-dir", dir); code != 0 {
		t.Fatal(code, out)
	}
	write(t, dir, "a.yaml", "name: a\nblock: [y.example]\n")
	ctx := context.Background()
	files, err := rulescli.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	steps, _, err := rulescli.Plan(ctx, c, testkit.OrgID, files)
	if err != nil {
		t.Fatal(err)
	}
	// 計画のあとに、画面などで変えられた。
	p := *steps[0].Current
	pol, _ := store.GetPolicy(ctx, p.ID)
	pol.Block = []string{"z.example"}
	if err := store.UpdatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if _, err := rulescli.Apply(ctx, c, testkit.OrgID, steps); err == nil || !strings.Contains(err.Error(), "plan からやり直す") {
		t.Fatal(err)
	}
	pol, _ = store.GetPolicy(ctx, p.ID)
	if pol.Block[0] != "z.example" {
		t.Fatal(pol.Block)
	}
}
