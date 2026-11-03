// Package rulescli はポリシーのルールをファイル（YAML）で管理する CLI（mdm rules）。ルールの API（ADR 0016）を呼ぶ。
//
//	mdm rules export -dir rules   今のポリシーをファイルに書き出す（始めるとき）
//	mdm rules plan   -dir rules   ファイルと今の違いを見せる（保存しない）
//	mdm rules apply  -dir rules   ファイルの中身にする
//
// つなぎ先と鍵は環境変数 MDM_RULES_URL・MDM_RULES_TOKEN、組織は MDM_ORG_ID（または -org）。
// ファイル 1 つが 1 つのポリシー。id があればそのポリシー、無ければ同じ名前のポリシー、それも無ければ作る。
// ファイルに無いポリシーは消さない（「管理していない」と出す）。
package rulescli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// Policy はルールの API のポリシー。
type Policy struct {
	ID      string         `json:"id"`
	OrgID   string         `json:"org_id"`
	Version string         `json:"version"`
	Policy  map[string]any `json:"policy"`
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
	Policy  Policy   `json:"policy"`
	Changes []Change `json:"changes"`
	Applied bool     `json:"applied"`
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

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
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
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
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

// List は組織のポリシーの一覧。
func (c *Client) List(ctx context.Context, org string) ([]Policy, error) {
	var out []Policy
	err := c.do(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(org)+"/policies", nil, &out)
	return out, err
}

// Create はポリシーを作る（dryRun なら作らない）。
func (c *Client) Create(ctx context.Context, org string, spec map[string]any, dryRun bool) (Result, error) {
	var out Result
	err := c.do(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(org)+"/policies", map[string]any{"policy": spec, "dry_run": dryRun}, &out)
	return out, err
}

// Replace はポリシーを丸ごと置き換える（dryRun なら置き換えない）。version が今の版と違えば 412。
func (c *Client) Replace(ctx context.Context, id string, spec map[string]any, version string, dryRun bool) (Result, error) {
	var out Result
	body := map[string]any{"policy": spec, "dry_run": dryRun}
	if version != "" {
		body["expected_version"] = version
	}
	err := c.do(ctx, http.MethodPut, "/v1/policies/"+url.PathEscape(id), body, &out)
	return out, err
}

// File はルールのファイル 1 つ。
type File struct {
	Path string
	ID   string
	Name string
	// Spec は id を除いた中身（ルールの API の policy）。
	Spec map[string]any
}

// LoadDir は dir の *.yaml・*.yml を読む。名前と id の重なりは誤り。
func LoadDir(dir string) ([]File, error) {
	var paths []string
	for _, pat := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s にルールのファイル（*.yaml）が無い", dir)
	}
	var files []File
	names, ids := map[string]string{}, map[string]string{}
	for _, p := range paths {
		f, err := loadFile(p)
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
	return files, nil
}

func loadFile(path string) (File, error) {
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
	f := File{Path: path, Spec: m}
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
	Current *Policy // nil なら作る
	Result  Result
}

// Plan はファイルと今のポリシーを比べる（保存しない）。unmanaged はファイルに無いポリシー。
func Plan(ctx context.Context, c *Client, org string, files []File) (steps []Step, unmanaged []Policy, err error) {
	cur, err := c.List(ctx, org)
	if err != nil {
		return nil, nil, err
	}
	byID, byName := map[string]*Policy{}, map[string][]*Policy{}
	for i := range cur {
		p := &cur[i]
		byID[p.ID] = p
		n, _ := p.Policy["name"].(string)
		byName[n] = append(byName[n], p)
	}
	used := map[string]bool{}
	for _, f := range files {
		var target *Policy
		if f.ID != "" {
			target = byID[f.ID]
			if target == nil {
				return nil, nil, fmt.Errorf("%s: id %s のポリシーがこの組織に無い", f.Path, f.ID)
			}
		} else if ps := byName[f.Name]; len(ps) > 1 {
			return nil, nil, fmt.Errorf("%s: 名前 %q のポリシーが %d つある。ファイルに id を書く", f.Path, f.Name, len(ps))
		} else if len(ps) == 1 {
			target = ps[0]
		}
		var res Result
		if target == nil {
			res, err = c.Create(ctx, org, f.Spec, true)
		} else {
			if used[target.ID] {
				return nil, nil, fmt.Errorf("%s: ポリシー %s をほかのファイルも指している", f.Path, target.ID)
			}
			used[target.ID] = true
			res, err = c.Replace(ctx, target.ID, f.Spec, target.Version, true)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		steps = append(steps, Step{File: f, Current: target, Result: res})
	}
	for _, p := range cur {
		if !used[p.ID] {
			unmanaged = append(unmanaged, p)
		}
	}
	return steps, unmanaged, nil
}

// Apply は計画したとおりに保存する。計画のあとにほかの人が変えていたら、そのポリシーで止まる（412）。
func Apply(ctx context.Context, c *Client, org string, steps []Step) ([]Result, error) {
	var out []Result
	for _, s := range steps {
		var res Result
		var err error
		switch {
		case s.Current == nil:
			res, err = c.Create(ctx, org, s.File.Spec, false)
		case len(s.Result.Changes) == 0:
			continue
		default:
			res, err = c.Replace(ctx, s.Current.ID, s.File.Spec, s.Current.Version, false)
		}
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusPreconditionFailed {
				return out, fmt.Errorf("%s: 計画のあとにポリシーが変えられた。plan からやり直す", s.File.Path)
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
		if s.Current == nil || len(s.Result.Changes) > 0 {
			return true
		}
	}
	return false
}

// PrintPlan は計画を人が読める形で書く。
func PrintPlan(w io.Writer, steps []Step, unmanaged []Policy) {
	for _, s := range steps {
		switch {
		case s.Current == nil:
			fmt.Fprintf(w, "+ %s（作る）  %s\n", s.File.Name, s.File.Path)
		case len(s.Result.Changes) == 0:
			fmt.Fprintf(w, "= %s（%s）変わらない\n", s.File.Name, s.Current.ID)
			continue
		default:
			fmt.Fprintf(w, "~ %s（%s）  %s\n", s.File.Name, s.Current.ID, s.File.Path)
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
	for _, p := range unmanaged {
		n, _ := p.Policy["name"].(string)
		fmt.Fprintf(w, "? %s（%s）ファイルに無い（変えない・消さない）\n", n, p.ID)
	}
}

// Export は組織のポリシーを dir にファイルとして書く。あるファイルは上書きしない。
func Export(ctx context.Context, c *Client, org, dir string) ([]string, error) {
	ps, err := c.List(ctx, org)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, p := range ps {
		path := filepath.Join(dir, fileName(p)+".yaml")
		if _, err := os.Stat(path); err == nil {
			return written, fmt.Errorf("%s がもうある（上書きしない）", path)
		}
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "# mdm rules export（%s）\n", p.ID)
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		doc := map[string]any{"id": p.ID}
		for k, v := range p.Policy {
			doc[k] = v
		}
		if err := enc.Encode(doc); err != nil {
			return written, err
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// fileName はファイルの名前（ポリシーの id。名前は日本語や記号を含みうるので使わない）。
func fileName(p Policy) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, p.ID)
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
			n, _ := r.Policy.Policy["name"].(string)
			fmt.Fprintf(stdout, "反映した: %s（%s）\n", n, r.Policy.ID)
		}
		if err != nil {
			return fail(err)
		}
		return 0
	}
	return usage()
}
