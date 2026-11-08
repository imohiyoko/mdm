// Package rulescli はポリシーと自動のルールをファイル（YAML）で管理する CLI（mdm rules）。ルールの API（ADR 0016）を呼ぶ。
//
//	mdm rules export -dir rules   今のポリシーをファイルに書き出す（始めるとき）
//	mdm rules plan   -dir rules   ファイルと今の違いを見せる（保存しない）
//	mdm rules apply  -dir rules   ファイルの中身にする
//
// つなぎ先と鍵は環境変数 MDM_RULES_URL・MDM_RULES_TOKEN、組織は MDM_ORG_ID（または -org）。
// rules/*.yaml の 1 つが 1 つのポリシー、rules/automations/*.yaml の 1 つが 1 つの自動のルール（ADR 0017）。
// id があればそれ、無ければ同じ名前のもの、それも無ければ作る。ファイルに無いものは消さない（「管理していない」と出す）。
package rulescli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Client はルールの API を呼ぶ。
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Kind はファイルで管理するものの種類（ポリシー・自動のルール）。
type Kind struct {
	Label string // 人に見せる名前
	Field string // API の中身の項目（policy・automation）
	Coll  string // API の道（policies・automations）
	Dir   string // ルールの場所の中のフォルダー（空ならそのまま）
}

var (
	// KindPolicy はポリシー（rules/*.yaml）。
	KindPolicy = &Kind{Label: "ポリシー", Field: "policy", Coll: "policies"}
	// KindAutomation は自動のルール（rules/automations/*.yaml）。ポリシーのあとに反映する。
	KindAutomation = &Kind{Label: "自動のルール", Field: "automation", Coll: "automations", Dir: "automations"}
	kinds          = []*Kind{KindPolicy, KindAutomation}
)

// Resource はルールの API のポリシーか自動のルール。
type Resource struct {
	Kind    *Kind          `json:"-"`
	ID      string         `json:"id"`
	OrgID   string         `json:"org_id"`
	Version string         `json:"version"`
	Spec    map[string]any `json:"-"`
}

// Name は中身の名前。
func (r Resource) Name() string {
	n, _ := r.Spec["name"].(string)
	return n
}

func (r *Resource) UnmarshalJSON(b []byte) error {
	type plain Resource
	var raw struct {
		plain
		Policy     map[string]any `json:"policy"`
		Automation map[string]any `json:"automation"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*r = Resource(raw.plain)
	r.Spec = raw.Policy
	if raw.Automation != nil {
		r.Spec = raw.Automation
	}
	return nil
}

// Change は変わる項目。
type Change struct {
	Field   string   `json:"field"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	From    string   `json:"from"`
	To      string   `json:"to"`
}

// Result は作る・置き換えるの答え。
type Result struct {
	Resource Resource `json:"-"`
	Changes  []Change `json:"changes"`
	Applied  bool     `json:"applied"`
}

func (r *Result) UnmarshalJSON(b []byte) error {
	var raw struct {
		Policy     *Resource `json:"policy"`
		Automation *Resource `json:"automation"`
		Changes    []Change  `json:"changes"`
		Applied    bool      `json:"applied"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	r.Changes, r.Applied = raw.Changes, raw.Applied
	switch {
	case raw.Policy != nil:
		r.Resource = *raw.Policy
	case raw.Automation != nil:
		r.Resource = *raw.Automation
	}
	return nil
}

// APIError はルールの API のエラー。
type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("%d %s", e.Status, e.Code)
}

// checkBaseURL は、鍵（Bearer）を平文で送らないように、https か手元（ループバック）の http だけを許す。
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" && u.User == nil {
		if u.Scheme == "https" {
			return nil
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		if u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("MDM_RULES_URL は https://host[:port]（手元の http://127.0.0.1:port も可）")
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if err := checkBaseURL(c.BaseURL); err != nil {
		return err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	// 転送の先にも同じ制限をかける（同じホストへの転送では Go は Authorization を引き継ぐので、
	// https から http への転送で鍵が平文で送られうる）。
	next := hc.CheckRedirect
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if err := checkBaseURL(r.URL.String()); err != nil {
			return fmt.Errorf("転送の先: %w", err)
		}
		if next != nil {
			return next(r, via)
		}
		if len(via) >= 10 {
			return errors.New("転送が多すぎる")
		}
		return nil
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, e)
		return e
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// List は組織のポリシーか自動のルールの一覧。
func (c *Client) List(ctx context.Context, k *Kind, org string) ([]Resource, error) {
	var out []Resource
	err := c.do(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(org)+"/"+k.Coll, nil, &out)
	for i := range out {
		out[i].Kind = k
	}
	return out, err
}

// Create は作る（dryRun なら作らない）。
func (c *Client) Create(ctx context.Context, k *Kind, org string, spec map[string]any, dryRun bool) (Result, error) {
	var out Result
	err := c.do(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(org)+"/"+k.Coll, map[string]any{k.Field: spec, "dry_run": dryRun}, &out)
	out.Resource.Kind = k
	return out, err
}

// Replace は丸ごと置き換える（dryRun なら置き換えない）。version が今の版と違えば 412。
func (c *Client) Replace(ctx context.Context, k *Kind, id string, spec map[string]any, version string, dryRun bool) (Result, error) {
	var out Result
	body := map[string]any{k.Field: spec, "dry_run": dryRun}
	if version != "" {
		body["expected_version"] = version
	}
	err := c.do(ctx, http.MethodPut, "/v1/"+k.Coll+"/"+url.PathEscape(id), body, &out)
	out.Resource.Kind = k
	return out, err
}

// File はルールのファイル 1 つ。
type File struct {
	Kind *Kind
	Path string
	ID   string
	Name string
	// Spec は id を除いた中身（ルールの API の policy・automation）。
	Spec map[string]any
}

// LoadDir は dir の *.yaml・*.yml（ポリシー）と dir/automations の *.yaml・*.yml（自動のルール）を読む。
// 種類ごとに、名前と id の重なりは誤り。
func LoadDir(dir string) ([]File, error) {
	var files []File
	for _, k := range kinds {
		var paths []string
		for _, pat := range []string{"*.yaml", "*.yml"} {
			m, err := filepath.Glob(filepath.Join(dir, k.Dir, pat))
			if err != nil {
				return nil, err
			}
			paths = append(paths, m...)
		}
		sort.Strings(paths)
		names, ids := map[string]string{}, map[string]string{}
		for _, p := range paths {
			f, err := loadFile(k, p)
			if err != nil {
				return nil, err
			}
			if prev, ok := names[f.Name]; ok {
				return nil, fmt.Errorf("%s と %s が同じ名前 %q", prev, p, f.Name)
			}
			names[f.Name] = p
			if f.ID != "" {
				if prev, ok := ids[f.ID]; ok {
					return nil, fmt.Errorf("%s と %s が同じ id %q", prev, p, f.ID)
				}
				ids[f.ID] = p
			}
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s にルールのファイル（*.yaml）が無い", dir)
	}
	return files, nil
}

func loadFile(k *Kind, path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	if m == nil {
		return File{}, fmt.Errorf("%s: 空のファイル", path)
	}
	f := File{Kind: k, Path: path, Spec: m}
	if v, ok := m["id"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return File{}, fmt.Errorf("%s: id は文字列", path)
		}
		f.ID = s
		delete(m, "id")
	}
	name, _ := m["name"].(string)
	if strings.TrimSpace(name) == "" {
		return File{}, fmt.Errorf("%s: name が要る", path)
	}
	f.Name = name
	return f, nil
}

// Step は 1 つのファイルの計画。
type Step struct {
	File    File
	Current *Resource // nil なら作る
	Result  Result
	// Waits は、このファイルの計画が、同じ apply で作るポリシー（この名前）を待っていること。
	// そのポリシーができるまで API は確かめられないので、apply のときに確かめる。
	Waits string
}

// Plan はファイルと今のものを比べる（保存しない）。unmanaged はファイルに無いもの。
// ポリシーを先に、自動のルールをあとに並べる（自動のルールはポリシーを使うため）。
func Plan(ctx context.Context, c *Client, org string, files []File) (steps []Step, unmanaged []Resource, err error) {
	creating := map[string]bool{} // この計画で作るポリシーの名前
	for _, k := range kinds {
		cur, err := c.List(ctx, k, org)
		if err != nil {
			return nil, nil, err
		}
		byID, byName := map[string]*Resource{}, map[string][]*Resource{}
		for i := range cur {
			r := &cur[i]
			byID[r.ID] = r
			byName[r.Name()] = append(byName[r.Name()], r)
		}
		used := map[string]bool{}
		for _, f := range files {
			if f.Kind != k {
				continue
			}
			var target *Resource
			if f.ID != "" {
				target = byID[f.ID]
				if target == nil {
					return nil, nil, fmt.Errorf("%s: id %s の%sがこの組織に無い", f.Path, f.ID, k.Label)
				}
			} else if rs := byName[f.Name]; len(rs) > 1 {
				return nil, nil, fmt.Errorf("%s: 名前 %q の%sが %d つある。ファイルに id を書く", f.Path, f.Name, k.Label, len(rs))
			} else if len(rs) == 1 {
				target = rs[0]
			}
			if target != nil {
				if used[target.ID] {
					return nil, nil, fmt.Errorf("%s: %s %s をほかのファイルも指している", f.Path, k.Label, target.ID)
				}
				used[target.ID] = true
			}
			var res Result
			if target == nil {
				res, err = c.Create(ctx, k, org, f.Spec, true)
			} else {
				res, err = c.Replace(ctx, k, target.ID, f.Spec, target.Version, true)
			}
			step := Step{File: f, Current: target, Result: res}
			if err != nil {
				ref, _ := f.Spec["policy"].(string)
				var ae *APIError
				if k != KindAutomation || !creating[ref] || !errors.As(err, &ae) || ae.Status != http.StatusBadRequest {
					return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
				}
				step.Waits = ref
			}
			if k == KindPolicy && target == nil {
				creating[f.Name] = true
			}
			steps = append(steps, step)
		}
		for _, r := range cur {
			if !used[r.ID] {
				unmanaged = append(unmanaged, r)
			}
		}
	}
	return steps, unmanaged, nil
}

// Apply は計画したとおりに保存する。計画のあとにほかの人が変えていたら、そこで止まる（412）。
func Apply(ctx context.Context, c *Client, org string, steps []Step) ([]Result, error) {
	var out []Result
	for _, s := range steps {
		var res Result
		var err error
		k := s.File.Kind
		switch {
		case s.Current == nil:
			res, err = c.Create(ctx, k, org, s.File.Spec, false)
		case len(s.Result.Changes) == 0 && s.Waits == "":
			continue
		default:
			res, err = c.Replace(ctx, k, s.Current.ID, s.File.Spec, s.Current.Version, false)
		}
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusPreconditionFailed {
				return out, fmt.Errorf("%s: 計画のあとに%sが変えられた。plan からやり直す", s.File.Path, k.Label)
			}
			return out, fmt.Errorf("%s: %w", s.File.Path, err)
		}
		out = append(out, res)
	}
	return out, nil
}

// HasChanges は計画に変わるものがあるか。
func HasChanges(steps []Step) bool {
	for _, s := range steps {
		if s.Current == nil || len(s.Result.Changes) > 0 || s.Waits != "" {
			return true
		}
	}
	return false
}

// PrintPlan は計画を人が読める形で書く。
func PrintPlan(w io.Writer, steps []Step, unmanaged []Resource) {
	for _, s := range steps {
		label := s.File.Name
		if s.File.Kind == KindAutomation {
			label = "自動のルール " + label
		}
		wait := ""
		if s.Waits != "" {
			wait = fmt.Sprintf("。ポリシー %s を作ってから確かめる", s.Waits)
		}
		switch {
		case s.Current == nil:
			fmt.Fprintf(w, "+ %s（作る%s）  %s\n", label, wait, s.File.Path)
		case s.Waits != "":
			fmt.Fprintf(w, "~ %s（%s%s）  %s\n", label, s.Current.ID, wait, s.File.Path)
			continue
		case len(s.Result.Changes) == 0:
			fmt.Fprintf(w, "= %s（%s）変わらない\n", label, s.Current.ID)
			continue
		default:
			fmt.Fprintf(w, "~ %s（%s）  %s\n", label, s.Current.ID, s.File.Path)
		}
		for _, ch := range s.Result.Changes {
			if s.Current == nil && ch.From == "" && len(ch.Added) == 0 && len(ch.Removed) == 0 {
				continue
			}
			var parts []string
			for _, a := range ch.Added {
				parts = append(parts, "+ "+a)
			}
			for _, r := range ch.Removed {
				parts = append(parts, "- "+r)
			}
			if ch.From != "" || ch.To != "" {
				parts = append(parts, ch.From+" → "+ch.To)
			}
			fmt.Fprintf(w, "    %s: %s\n", ch.Field, strings.Join(parts, "  "))
		}
	}
	for _, r := range unmanaged {
		label := r.Name()
		if r.Kind == KindAutomation {
			label = "自動のルール " + label
		}
		fmt.Fprintf(w, "? %s（%s）ファイルに無い（変えない・消さない）\n", label, r.ID)
	}
}

// Export は組織のポリシーを dir に、自動のルールを dir/automations にファイルとして書く。あるファイルは上書きしない。
// 自動のルールのポリシーは、組織の中で名前が 1 つだけなら名前で書く（読みやすいように）。
func Export(ctx context.Context, c *Client, org, dir string) ([]string, error) {
	var written []string
	names := map[string]string{} // ポリシーの ID → 名前（重なる名前は入れない）
	count := map[string]int{}
	for _, k := range kinds {
		rs, err := c.List(ctx, k, org)
		if err != nil {
			return written, err
		}
		if k == KindPolicy {
			for _, r := range rs {
				count[r.Name()]++
			}
			for _, r := range rs {
				if count[r.Name()] == 1 {
					names[r.ID] = r.Name()
				}
			}
		}
		if len(rs) == 0 {
			continue
		}
		d := filepath.Join(dir, k.Dir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return written, err
		}
		for _, r := range rs {
			path := filepath.Join(d, fileName(r.ID)+".yaml")
			if _, err := os.Stat(path); err == nil {
				return written, fmt.Errorf("%s がもうある（上書きしない）", path)
			}
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "# mdm rules export（%s）\n", r.ID)
			enc := yaml.NewEncoder(&buf)
			enc.SetIndent(2)
			doc := map[string]any{"id": r.ID}
			for k, v := range r.Spec {
				doc[k] = v
			}
			if k == KindAutomation {
				if id, _ := doc["policy"].(string); names[id] != "" {
					doc["policy"] = names[id]
				}
			}
			if err := enc.Encode(doc); err != nil {
				return written, err
			}
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				return written, err
			}
			written = append(written, path)
		}
	}
	return written, nil
}

// fileName はファイルの名前（ID。名前は日本語や記号を含みうるので使わない）。
func fileName(id string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, id)
}

// Main は mdm rules のコマンド。終了コードを返す。
func Main(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "使い方: mdm rules plan|apply|export [-dir rules] [-org org_...] [-detailed-exitcode]\n  環境変数 MDM_RULES_URL（例 https://mdm.example:8093）・MDM_RULES_TOKEN・MDM_ORG_ID")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	cmd := args[0]
	fs := flag.NewFlagSet("rules "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "rules", "ルールのファイルの場所")
	org := fs.String("org", os.Getenv("MDM_ORG_ID"), "組織の id")
	detailed := fs.Bool("detailed-exitcode", false, "plan で、変わるものがあれば終了コード 2")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	c := &Client{BaseURL: os.Getenv("MDM_RULES_URL"), Token: os.Getenv("MDM_RULES_TOKEN")}
	if c.BaseURL == "" || c.Token == "" || *org == "" {
		fmt.Fprintln(stderr, "MDM_RULES_URL・MDM_RULES_TOKEN と組織（MDM_ORG_ID か -org）が要る")
		return 2
	}
	ctx := context.Background()
	fail := func(err error) int {
		fmt.Fprintln(stderr, "エラー:", err)
		return 1
	}
	switch cmd {
	case "export":
		paths, err := Export(ctx, c, *org, *dir)
		for _, p := range paths {
			fmt.Fprintln(stdout, "書いた:", p)
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "plan", "apply":
		files, err := LoadDir(*dir)
		if err != nil {
			return fail(err)
		}
		steps, unmanaged, err := Plan(ctx, c, *org, files)
		if err != nil {
			return fail(err)
		}
		PrintPlan(stdout, steps, unmanaged)
		if cmd == "plan" {
			if *detailed && HasChanges(steps) {
				return 2
			}
			return 0
		}
		if !HasChanges(steps) {
			fmt.Fprintln(stdout, "変えるものは無い")
			return 0
		}
		res, err := Apply(ctx, c, *org, steps)
		for _, r := range res {
			fmt.Fprintf(stdout, "反映した: %s（%s）\n", r.Resource.Name(), r.Resource.ID)
		}
		if err != nil {
			return fail(err)
		}
		return 0
	}
	return usage()
}
