package adminapi

// ルールの API（ADR 0016）。ポリシーのルールの読み書きと「今すぐ止める」を、imohiyoko/API の定義から作る別の口で出す。
// AI のエージェント・自動化・IaC（ルールのファイルを GitHub で管理して plan・apply する）から使う。
//
// 認証は管理の API と同じ（設定の鍵か IAM のアクセストークン）。認可は MDM の組織の役割で決める（port.Authorizer）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/imohiyoko/API/define"
	"github.com/imohiyoko/API/port"
	apiruntime "github.com/imohiyoko/API/runtime"

	"github.com/imohiyoko/mdm/core"
)

// 契約（api/rules）の名前と版。
const (
	RulesAPITitle   = "MDM ルールの API"
	RulesAPIVersion = "0.1.0"
)

var policyMu sync.Mutex // ポリシーを読んでから書くまでのあいだに、ほかの書き込みを割り込ませない（版の確かめ）

// --- 型（API に出す形）

type rulesWindow struct {
	Days  []string `api:"days,optional"`
	Start string   `api:"start"`
	End   string   `api:"end"`
}

type rulesApps struct {
	Mode     string   `api:"mode,optional"`
	Required []string `api:"required,optional"`
	Allowed  []string `api:"allowed,optional"`
	Blocked  []string `api:"blocked,optional"`
}

type rulesDevice struct {
	CameraDisabled        bool `api:"camera_disabled,optional"`
	ScreenCaptureDisabled bool `api:"screen_capture_disabled,optional"`
	FactoryResetDisabled  bool `api:"factory_reset_disabled,optional"`
	VPNConfigDisabled     bool `api:"vpn_config_disabled,optional"`
	PasscodeMinLength     int  `api:"passcode_min_length,optional"`
}

type rulesOSVersions struct {
	Android string `api:"android,optional"`
	IOS     string `api:"ios,optional"`
	MacOS   string `api:"macos,optional"`
	Windows string `api:"windows,optional"`
}

type rulesCompliance struct {
	RequireEncryption bool            `api:"require_encryption,optional"`
	RequireScreenLock bool            `api:"require_screen_lock,optional"`
	MaxReportAgeHours int             `api:"max_report_age_hours,optional"`
	MinOSVersion      rulesOSVersions `api:"min_os_version,optional"`
}

type rulesWiFi struct {
	SSID   string `api:"ssid"`
	Hidden bool   `api:"hidden,optional"`
}

// rulesSpec はポリシーのルール。IaC のファイルに書く中身と同じ。書かない項目は空（既定）になる。
type rulesSpec struct {
	Name        string          `api:"name"`
	Mode        string          `api:"mode,optional"`
	Allow       []string        `api:"allow,optional"`
	Block       []string        `api:"block,optional"`
	Blocklists  []string        `api:"blocklists,optional"`
	QuietHours  []rulesWindow   `api:"quiet_hours,optional"`
	TimeZone    string          `api:"time_zone,optional"`
	LogQueries  bool            `api:"log_queries,optional"`
	Device      rulesDevice     `api:"device,optional"`
	AndroidApps rulesApps       `api:"android_apps,optional"`
	AppleApps   rulesApps       `api:"apple_apps,optional"`
	WindowsApps rulesApps       `api:"windows_apps,optional"`
	Compliance  rulesCompliance `api:"compliance,optional"`
	WiFi        []rulesWiFi     `api:"wifi,optional"`
}

type rulesPolicy struct {
	ID    string `api:"id"`
	OrgID string `api:"org_id"`
	// Version は中身から決まる版。replace・edit の expected_version に渡すと、ほかの人が先に変えていたら書き込まない。
	Version   string    `api:"version"`
	Policy    rulesSpec `api:"policy"`
	UpdatedAt time.Time `api:"updated_at"`
}

// rulesChange は変わる項目。リストは足すもの・消すもの、ほかは前と後の値（JSON）。
type rulesChange struct {
	Field   string   `api:"field"`
	Added   []string `api:"added,optional"`
	Removed []string `api:"removed,optional"`
	From    string   `api:"from,optional"`
	To      string   `api:"to,optional"`
}

type rulesResult struct {
	Policy  rulesPolicy   `api:"policy"`
	Changes []rulesChange `api:"changes"`
	// Applied は保存したか（dry_run なら false）。
	Applied bool `api:"applied"`
}

type rulesOrgIn struct {
	OrgID string `api:"org_id,path"`
}

type rulesIDIn struct {
	ID string `api:"id,path"`
}

type rulesCreateIn struct {
	OrgID  string    `api:"org_id,path"`
	Policy rulesSpec `api:"policy"`
	DryRun bool      `api:"dry_run,optional"`
}

type rulesReplaceIn struct {
	ID              string    `api:"id,path"`
	Policy          rulesSpec `api:"policy"`
	ExpectedVersion string    `api:"expected_version,optional"`
	DryRun          bool      `api:"dry_run,optional"`
}

type rulesEditIn struct {
	ID              string   `api:"id,path"`
	AddBlock        []string `api:"add_block,optional"`
	RemoveBlock     []string `api:"remove_block,optional"`
	AddAllow        []string `api:"add_allow,optional"`
	RemoveAllow     []string `api:"remove_allow,optional"`
	ExpectedVersion string   `api:"expected_version,optional"`
	DryRun          bool     `api:"dry_run,optional"`
}

type rulesDeviceOut struct {
	ID          string     `api:"id"`
	OrgID       string     `api:"org_id"`
	Name        string     `api:"name"`
	Platform    string     `api:"platform"`
	PersonID    string     `api:"person_id"`
	PolicyID    string     `api:"policy_id"`
	PausedUntil *time.Time `api:"paused_until,optional"`
}

type rulesPauseIn struct {
	ID      string `api:"id,path"`
	Minutes int    `api:"minutes"`
}

// --- 変換

func specFromPolicy(p core.Policy) rulesSpec {
	j := toPolicyJSON(p)
	apps := func(a appRulesJSON) rulesApps {
		return rulesApps{Mode: string(a.Mode), Required: a.Required, Allowed: a.Allowed, Blocked: a.Blocked}
	}
	sp := rulesSpec{
		Name: j.Name, Mode: string(j.Mode), Allow: j.Allow, Block: j.Block, Blocklists: j.Blocklists,
		TimeZone: j.TimeZone, LogQueries: j.LogQueries, Device: rulesDevice(j.Device),
		AndroidApps: apps(j.Android), AppleApps: apps(j.Apple), WindowsApps: apps(j.Windows),
		Compliance: rulesCompliance{RequireEncryption: j.Compliance.RequireEncryption, RequireScreenLock: j.Compliance.RequireScreenLock,
			MaxReportAgeHours: j.Compliance.MaxReportAgeHours, MinOSVersion: rulesOSVersions{
				Android: j.Compliance.MinOSVersion[core.PlatformAndroid], IOS: j.Compliance.MinOSVersion[core.PlatformIOS],
				MacOS: j.Compliance.MinOSVersion[core.PlatformMacOS], Windows: j.Compliance.MinOSVersion[core.PlatformWindows]}},
		QuietHours: []rulesWindow{}, WiFi: []rulesWiFi{},
	}
	for _, w := range j.QuietHours {
		sp.QuietHours = append(sp.QuietHours, rulesWindow{Days: nonNil(w.Days), Start: w.Start, End: w.End})
	}
	for _, w := range j.WiFi {
		sp.WiFi = append(sp.WiFi, rulesWiFi(w))
	}
	return sp
}

// toPolicy は管理の API と同じ確かめ（policyInput.toPolicy）で、ルールをポリシーにする。
func (sp rulesSpec) toPolicy(id, orgID string) (core.Policy, error) {
	apps := func(a rulesApps) appRulesJSON {
		return appRulesJSON{Mode: core.AppMode(a.Mode), Required: a.Required, Allowed: a.Allowed, Blocked: a.Blocked}
	}
	in := policyInput{
		OrgID: orgID, Name: sp.Name, Mode: core.FilterMode(sp.Mode), Allow: sp.Allow, Block: sp.Block, Blocklists: sp.Blocklists,
		TimeZone: sp.TimeZone, LogQueries: sp.LogQueries, Device: deviceRulesJSON(sp.Device),
		Android: apps(sp.AndroidApps), Apple: apps(sp.AppleApps), Windows: apps(sp.WindowsApps),
		Compliance: complianceJSON{RequireEncryption: sp.Compliance.RequireEncryption, RequireScreenLock: sp.Compliance.RequireScreenLock,
			MaxReportAgeHours: sp.Compliance.MaxReportAgeHours, MinOSVersion: map[core.Platform]string{}},
	}
	for pl, v := range map[core.Platform]string{core.PlatformAndroid: sp.Compliance.MinOSVersion.Android, core.PlatformIOS: sp.Compliance.MinOSVersion.IOS,
		core.PlatformMacOS: sp.Compliance.MinOSVersion.MacOS, core.PlatformWindows: sp.Compliance.MinOSVersion.Windows} {
		if v != "" {
			in.Compliance.MinOSVersion[pl] = v
		}
	}
	for _, w := range sp.QuietHours {
		in.QuietHours = append(in.QuietHours, windowJSON(w))
	}
	for _, w := range sp.WiFi {
		in.WiFi = append(in.WiFi, wifiJSON(w))
	}
	return in.toPolicy(id)
}

// policyVersion はポリシーの中身（更新の時刻を除く）から決まる版。
func policyVersion(p core.Policy) string {
	j := toPolicyJSON(p)
	j.UpdatedAt = time.Time{}
	b, _ := json.Marshal(j)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func toRulesPolicy(p core.Policy) rulesPolicy {
	return rulesPolicy{ID: p.ID, OrgID: p.OrgID, Version: policyVersion(p), Policy: specFromPolicy(p), UpdatedAt: p.UpdatedAt}
}

// diffRules は a から b への変わる項目を、項目の名前の順に返す。
func diffRules(a, b rulesSpec) []rulesChange {
	flat := func(sp rulesSpec) map[string]any {
		raw, _ := json.Marshal(specJSON(sp))
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		out := map[string]any{}
		var walk func(prefix string, v any)
		walk = func(prefix string, v any) {
			if o, ok := v.(map[string]any); ok {
				for k, x := range o {
					walk(prefix+k+".", x)
				}
				return
			}
			out[prefix[:len(prefix)-1]] = v
		}
		walk("", m)
		return out
	}
	fa, fb := flat(a), flat(b)
	keys := make([]string, 0, len(fa))
	for k := range fa {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changes := []rulesChange{}
	for _, k := range keys {
		va, vb := fa[k], fb[k]
		ja, _ := json.Marshal(va)
		jb, _ := json.Marshal(vb)
		if string(ja) == string(jb) {
			continue
		}
		la, okA := stringList(va)
		lb, okB := stringList(vb)
		if okA && okB {
			c := rulesChange{Field: k, Added: []string{}, Removed: []string{}}
			for _, x := range lb {
				if !slices.Contains(la, x) {
					c.Added = append(c.Added, x)
				}
			}
			for _, x := range la {
				if !slices.Contains(lb, x) {
					c.Removed = append(c.Removed, x)
				}
			}
			if len(c.Added) == 0 && len(c.Removed) == 0 { // 順番だけが変わった
				c.From, c.To = string(ja), string(jb)
			}
			changes = append(changes, c)
			continue
		}
		changes = append(changes, rulesChange{Field: k, From: string(ja), To: string(jb)})
	}
	return changes
}

// specJSON は差分を取るための JSON の形（API の名前と同じ）。
func specJSON(sp rulesSpec) map[string]any {
	apps := func(a rulesApps) map[string]any {
		return map[string]any{"mode": a.Mode, "required": nonNil(a.Required), "allowed": nonNil(a.Allowed), "blocked": nonNil(a.Blocked)}
	}
	return map[string]any{
		"name": sp.Name, "mode": sp.Mode, "allow": nonNil(sp.Allow), "block": nonNil(sp.Block), "blocklists": nonNil(sp.Blocklists),
		"quiet_hours": sp.QuietHours, "time_zone": sp.TimeZone, "log_queries": sp.LogQueries,
		"device": map[string]any{"camera_disabled": sp.Device.CameraDisabled, "screen_capture_disabled": sp.Device.ScreenCaptureDisabled,
			"factory_reset_disabled": sp.Device.FactoryResetDisabled, "vpn_config_disabled": sp.Device.VPNConfigDisabled,
			"passcode_min_length": sp.Device.PasscodeMinLength},
		"android_apps": apps(sp.AndroidApps), "apple_apps": apps(sp.AppleApps), "windows_apps": apps(sp.WindowsApps),
		"compliance": map[string]any{"require_encryption": sp.Compliance.RequireEncryption, "require_screen_lock": sp.Compliance.RequireScreenLock,
			"max_report_age_hours": sp.Compliance.MaxReportAgeHours,
			"min_os_version": map[string]any{"android": sp.Compliance.MinOSVersion.Android, "ios": sp.Compliance.MinOSVersion.IOS,
				"macos": sp.Compliance.MinOSVersion.MacOS, "windows": sp.Compliance.MinOSVersion.Windows}},
		"wifi": sp.WiFi,
	}
}

func stringList(v any) ([]string, bool) {
	xs, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// --- 認証と認可

// rulesAuth は port.Authenticator と port.Authorizer。トークンの確かめ（イントロスペクション）は短いあいだ覚え、
// 認可と記録でもう一度 IAM に問い合わせない。
type rulesAuth struct {
	s     *Server
	mu    sync.Mutex
	cache map[[32]byte]rulesCached
}

type rulesCached struct {
	p   *Principal
	exp time.Time
}

const (
	rulesAuthTTL   = 30 * time.Second
	rulesAuthCache = 10000
)

func (a *rulesAuth) resolve(ctx context.Context, token string) (*Principal, bool) {
	key := sha256.Sum256([]byte(token))
	now := a.s.Clock.Now()
	a.mu.Lock()
	if c, ok := a.cache[key]; ok && now.Before(c.exp) {
		a.mu.Unlock()
		return c.p, true
	}
	a.mu.Unlock()
	p, ok := a.s.principalForToken(ctx, token, false)
	if !ok {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil || len(a.cache) >= rulesAuthCache {
		a.cache = map[[32]byte]rulesCached{} // 多すぎれば捨てて作り直す（覚えているのは 30 秒だけ）
	}
	a.cache[key] = rulesCached{p: p, exp: now.Add(rulesAuthTTL)}
	return p, true
}

func (a *rulesAuth) Authenticate(ctx context.Context, token string) (port.Principal, error) {
	p, ok := a.resolve(ctx, token)
	if !ok || len(p.Roles) == 0 {
		return port.Principal{}, port.ErrUnauthenticated
	}
	if p.Subject == "" { // 設定の鍵（自動化）
		return port.Principal{Type: port.PrincipalServiceAccount, ID: "token:" + p.Name, OrgID: p.Roles[0].OrgID, Token: token}, nil
	}
	return port.Principal{Type: port.PrincipalUser, ID: p.Subject, Token: token}, nil
}

func (a *rulesAuth) Check(ctx context.Context, req port.CheckRequest) (port.Decision, error) {
	deny := port.Decision{Reasons: []string{"not_allowed"}}
	p, ok := a.resolve(ctx, req.Principal.Token)
	if !ok {
		return deny, nil
	}
	var org string
	switch req.ResourceType {
	case "org":
		if req.ResourceID == "" {
			return deny, nil
		}
		org = req.ResourceID
	case "policy":
		pol, err := a.s.Store.GetPolicy(ctx, req.ResourceID)
		if errors.Is(err, core.ErrNotFound) {
			return deny, nil // 有るかどうかも見せない
		}
		if err != nil {
			return port.Decision{}, err
		}
		org = pol.OrgID
	case "device":
		d, err := a.s.Store.GetDevice(ctx, req.ResourceID)
		if errors.Is(err, core.ErrNotFound) {
			return deny, nil
		}
		if err != nil {
			return port.Decision{}, err
		}
		org = d.OrgID
	default:
		return deny, nil
	}
	switch req.Action {
	case "rules:read":
		// サーバー全体のポリシー（org が空）は、読むだけなら誰でも（どの組織からも使える）。
		ok = p.CanRead(org)
	case "rules:write":
		ok = p.CanWrite(org)
	default:
		ok = false
	}
	if !ok {
		return deny, nil
	}
	return port.Decision{Allowed: true}, nil
}

// actor は記録に残す名前。
func (a *rulesAuth) actor(ctx context.Context) string {
	pp, ok := define.PrincipalFrom(ctx)
	if !ok {
		return ""
	}
	if p, ok := a.resolve(ctx, pp.Token); ok {
		return p.Name + "（ルールの API）"
	}
	return pp.ID
}

// --- 操作

func storeErr(err error) error {
	switch {
	case errors.Is(err, core.ErrNotFound):
		return define.Errorf(define.CodeNotFound, "見つからない")
	case errors.Is(err, core.ErrConflict):
		return define.Errorf(define.CodeConflict, "ほかと重なっている")
	}
	return err
}

func inputErr(err error) error {
	var b badRequest
	if errors.As(err, &b) {
		return define.Errorf(define.CodeInvalidArgument, "%s", b.Error())
	}
	var q quotaError
	if errors.As(err, &q) { // 412 は版の食い違いだけに使う（管理の API と同じ 409）
		return define.Errorf(define.CodeConflict, "%s", q.Error())
	}
	return storeErr(err)
}

// RulesRegistry はルールの API の操作の定義（契約ファイルの生成にも使う）。
func (s *Server) RulesRegistry() *define.Registry {
	a := &rulesAuth{s: s}
	return s.rulesRegistry(a)
}

func (s *Server) rulesRegistry(a *rulesAuth) *define.Registry {
	expose := define.Expose(define.Public, define.REST)
	read := define.RateLimit(define.Public, "120/min")
	write := define.RateLimit(define.Public, "60/min")

	listPolicies := define.Query[rulesOrgIn, []rulesPolicy]("rules.policies.list",
		define.Doc("組織のポリシーの一覧（その組織のものだけ。サーバー全体の既定のポリシーは入らない）"),
		define.Authz("rules:read", define.Resource("org", "org_id")),
		define.HTTP("GET /v1/orgs/{org_id}/policies"), expose, read,
	).Handle(func(ctx context.Context, in rulesOrgIn) ([]rulesPolicy, error) {
		ps, err := s.Store.ListPolicies(ctx)
		if err != nil {
			return nil, err
		}
		out := []rulesPolicy{}
		for _, p := range ps {
			if p.OrgID == in.OrgID {
				out = append(out, toRulesPolicy(p))
			}
		}
		return out, nil
	})

	getPolicy := define.Query[rulesIDIn, rulesPolicy]("rules.policies.get",
		define.Doc("ポリシーのルール"),
		define.Authz("rules:read", define.Resource("policy", "id")),
		define.HTTP("GET /v1/policies/{id}"), expose, read,
	).Handle(func(ctx context.Context, in rulesIDIn) (rulesPolicy, error) {
		p, err := s.Store.GetPolicy(ctx, in.ID)
		if err != nil {
			return rulesPolicy{}, storeErr(err)
		}
		return toRulesPolicy(p), nil
	})

	createPolicy := define.Command[rulesCreateIn, rulesResult]("rules.policies.create",
		define.Doc("組織にポリシーを作る。dry_run なら作らずに中身だけ返す"),
		define.Authz("rules:write", define.Resource("org", "org_id")),
		define.HTTP("POST /v1/orgs/{org_id}/policies"), expose, write,
	).Handle(func(ctx context.Context, in rulesCreateIn) (rulesResult, error) {
		if _, err := s.Store.GetOrg(ctx, in.OrgID); err != nil {
			return rulesResult{}, storeErr(err)
		}
		p, err := in.Policy.toPolicy(core.NewID("pol"), in.OrgID)
		if err == nil {
			err = s.checkListsCtx(ctx, p.ListIDs)
		}
		if err != nil {
			return rulesResult{}, inputErr(err)
		}
		p.UpdatedAt = s.Clock.Now()
		res := rulesResult{Policy: toRulesPolicy(p), Changes: diffRules(rulesSpec{}, specFromPolicy(p))}
		if in.DryRun {
			return res, nil
		}
		unlock, err := s.reserve(ctx, p.OrgID, limitPolicies)
		if err != nil {
			return rulesResult{}, inputErr(err)
		}
		defer unlock()
		if err := s.Store.CreatePolicy(ctx, p); err != nil {
			return rulesResult{}, storeErr(err)
		}
		s.changedAs(ctx, a.actor(ctx), p.OrgID, "policy.create", p.ID)
		res.Applied = true
		return res, nil
	})

	// apply は cur を next に置き換える（版の確かめ・dry_run・記録）。policyMu を持って呼ぶ。
	apply := func(ctx context.Context, cur, next core.Policy, expected string, dryRun bool) (rulesResult, error) {
		if expected != "" && expected != policyVersion(cur) {
			return rulesResult{}, define.Errorf(define.CodeFailedPrecondition, "ポリシーが先に変えられている（今の版 %s）。読み直してからやり直す", policyVersion(cur))
		}
		if err := s.checkListsCtx(ctx, next.ListIDs); err != nil {
			return rulesResult{}, inputErr(err)
		}
		changes := diffRules(specFromPolicy(cur), specFromPolicy(next))
		if len(changes) == 0 { // 変わらないなら書かない（何度 apply しても同じ）
			return rulesResult{Policy: toRulesPolicy(cur), Changes: changes}, nil
		}
		next.UpdatedAt = s.Clock.Now()
		res := rulesResult{Policy: toRulesPolicy(next), Changes: changes}
		if dryRun {
			return res, nil
		}
		if err := s.Store.UpdatePolicy(ctx, next); err != nil {
			return rulesResult{}, storeErr(err)
		}
		s.changedAs(ctx, a.actor(ctx), next.OrgID, "policy.update", next.ID)
		res.Applied = true
		return res, nil
	}

	replacePolicy := define.Command[rulesReplaceIn, rulesResult]("rules.policies.replace",
		define.Doc("ポリシーのルールを丸ごと置き換える（IaC の apply）。書かない項目は空になる。変わらなければ何もしない"),
		define.Authz("rules:write", define.Resource("policy", "id")),
		define.HTTP("PUT /v1/policies/{id}"), expose, write,
	).Handle(func(ctx context.Context, in rulesReplaceIn) (rulesResult, error) {
		policyMu.Lock()
		defer policyMu.Unlock()
		cur, err := s.Store.GetPolicy(ctx, in.ID)
		if err != nil {
			return rulesResult{}, storeErr(err)
		}
		next, err := in.Policy.toPolicy(cur.ID, cur.OrgID)
		if err != nil {
			return rulesResult{}, inputErr(err)
		}
		next.UpdatedAt = cur.UpdatedAt
		return apply(ctx, cur, next, in.ExpectedVersion, in.DryRun)
	})

	editPolicy := define.Command[rulesEditIn, rulesResult]("rules.policies.edit",
		define.Doc("ブロック・許可のドメインを足す・消す（ほかの項目は変えない）"),
		define.Authz("rules:write", define.Resource("policy", "id")),
		define.HTTP("POST /v1/policies/{id}/edit"), expose, write,
	).Handle(func(ctx context.Context, in rulesEditIn) (rulesResult, error) {
		policyMu.Lock()
		defer policyMu.Unlock()
		cur, err := s.Store.GetPolicy(ctx, in.ID)
		if err != nil {
			return rulesResult{}, storeErr(err)
		}
		sp := specFromPolicy(cur)
		edit := func(list, add, remove []string, field string) ([]string, error) {
			add, err := normalizeDomains(field, add)
			if err != nil {
				return nil, err
			}
			remove, err = normalizeDomains(field, remove)
			if err != nil {
				return nil, err
			}
			out := []string{}
			for _, d := range list {
				if !slices.Contains(remove, d) {
					out = append(out, d)
				}
			}
			for _, d := range add {
				if !slices.Contains(out, d) {
					out = append(out, d)
				}
			}
			return out, nil
		}
		if sp.Block, err = edit(sp.Block, in.AddBlock, in.RemoveBlock, "block"); err != nil {
			return rulesResult{}, inputErr(err)
		}
		if sp.Allow, err = edit(sp.Allow, in.AddAllow, in.RemoveAllow, "allow"); err != nil {
			return rulesResult{}, inputErr(err)
		}
		next, err := sp.toPolicy(cur.ID, cur.OrgID)
		if err != nil {
			return rulesResult{}, inputErr(err)
		}
		next.UpdatedAt = cur.UpdatedAt
		return apply(ctx, cur, next, in.ExpectedVersion, in.DryRun)
	})

	listDevices := define.Query[rulesOrgIn, []rulesDeviceOut]("rules.devices.list",
		define.Doc("組織の端末の一覧（使っているポリシーと、止めている時刻）"),
		define.Authz("rules:read", define.Resource("org", "org_id")),
		define.HTTP("GET /v1/orgs/{org_id}/devices"), expose, read,
	).Handle(func(ctx context.Context, in rulesOrgIn) ([]rulesDeviceOut, error) {
		ds, err := s.Store.ListDevices(ctx)
		if err != nil {
			return nil, err
		}
		out := []rulesDeviceOut{}
		for _, d := range ds {
			if d.OrgID == in.OrgID {
				out = append(out, s.rulesDevice(d))
			}
		}
		return out, nil
	})

	pause := define.Command[rulesPauseIn, rulesDeviceOut]("rules.devices.pause",
		define.Doc("端末の通信を今すぐ止める（許可の一覧のほかは通さない）。minutes は 1〜10080"),
		define.Authz("rules:write", define.Resource("device", "id")),
		define.HTTP("POST /v1/devices/{id}/pause"), expose, write,
	).Handle(func(ctx context.Context, in rulesPauseIn) (rulesDeviceOut, error) {
		if in.Minutes < 1 || in.Minutes > 7*24*60 {
			return rulesDeviceOut{}, define.Errorf(define.CodeInvalidArgument, "minutes は 1〜10080")
		}
		return s.setPause(ctx, a, in.ID, s.Clock.Now().Add(time.Duration(in.Minutes)*time.Minute), "device.pause")
	})

	resume := define.Command[rulesIDIn, rulesDeviceOut]("rules.devices.resume",
		define.Doc("止めていた端末を戻す"),
		define.Authz("rules:write", define.Resource("device", "id")),
		define.HTTP("DELETE /v1/devices/{id}/pause"), expose, write,
	).Handle(func(ctx context.Context, in rulesIDIn) (rulesDeviceOut, error) {
		return s.setPause(ctx, a, in.ID, time.Time{}, "device.unpause")
	})

	return define.NewRegistry(define.WithName("mdm_rules")).Add(listPolicies, getPolicy, createPolicy, replacePolicy, editPolicy, listDevices, pause, resume)
}

func (s *Server) rulesDevice(d core.Device) rulesDeviceOut {
	out := rulesDeviceOut{ID: d.ID, OrgID: d.OrgID, Name: d.Name, Platform: string(d.Platform), PersonID: d.PersonID, PolicyID: d.PolicyID}
	if d.PausedUntil.After(s.Clock.Now()) {
		t := d.PausedUntil
		out.PausedUntil = &t
	}
	return out
}

func (s *Server) setPause(ctx context.Context, a *rulesAuth, id string, until time.Time, action string) (rulesDeviceOut, error) {
	d, err := s.Store.GetDevice(ctx, id)
	if err != nil {
		return rulesDeviceOut{}, storeErr(err)
	}
	d.PausedUntil = until
	if err := s.Store.UpdateDevice(ctx, d); err != nil {
		return rulesDeviceOut{}, storeErr(err)
	}
	s.changedAs(ctx, a.actor(ctx), d.OrgID, action, d.ID)
	return s.rulesDevice(d), nil
}

// RulesAPI はルールの API の口（public の REST）を組み立てる。
func (s *Server) RulesAPI(logger *slog.Logger) (*apiruntime.Server, error) {
	a := &rulesAuth{s: s}
	// 呼ぶのは組織の管理者と、その自動化なので、エラーのメッセージ（直し方）も見せる。中身の分からないエラーは見せない。
	pub := apiruntime.DefaultAudienceConfig(define.Public)
	pub.Disclosure = apiruntime.DiscloseDetail
	srv, err := apiruntime.Build(s.rulesRegistry(a), apiruntime.Config{Authenticator: a, Authorizer: a, Logger: logger,
		Audiences: map[string]apiruntime.AudienceConfig{define.Public: pub}})
	if err != nil {
		return nil, fmt.Errorf("rules api: %w", err)
	}
	return srv, nil
}
