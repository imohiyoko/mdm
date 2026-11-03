package adminapi

// ルールの API の自動のルール（ADR 0017）。ポリシーと同じく、試しに送る（dry_run）・版の確かめ（expected_version）・
// 同じ中身なら書かない、を持つ。ポリシーとグループは ID か名前で書ける（ファイルに ID を書かずに済むように）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/imohiyoko/API/define"

	"github.com/imohiyoko/mdm/core"
)

var automationMu sync.Mutex // 自動のルールを読んでから書くまでのあいだに、ほかの書き込みを割り込ませない

// rulesAutomationSpec は自動のルール。IaC のファイルに書く中身と同じ。
type rulesAutomationSpec struct {
	Name string `api:"name"`
	// Disabled なら止めておく（書かなければ有効）。
	Disabled bool `api:"disabled,optional"`
	Priority int  `api:"priority,optional"`
	// Groups はグループの ID か名前。書かなければ組織のすべての端末。
	Groups []string `api:"groups,optional"`
	// Trigger は schedule（windows が要る）か noncompliant（reasons が要る）。
	Trigger  string        `api:"trigger"`
	Windows  []rulesWindow `api:"windows,optional"`
	TimeZone string        `api:"time_zone,optional"`
	Reasons  []string      `api:"reasons,optional"`
	// Policy は当たっているあいだ使うポリシーの ID か名前。
	Policy string `api:"policy"`
}

type rulesAutomation struct {
	ID         string              `api:"id"`
	OrgID      string              `api:"org_id"`
	Version    string              `api:"version"`
	Automation rulesAutomationSpec `api:"automation"`
	UpdatedAt  time.Time           `api:"updated_at"`
}

type rulesAutomationResult struct {
	Automation rulesAutomation `api:"automation"`
	Changes    []rulesChange   `api:"changes"`
	Applied    bool            `api:"applied"`
}

type rulesAutomationCreateIn struct {
	OrgID      string              `api:"org_id,path"`
	Automation rulesAutomationSpec `api:"automation"`
	DryRun     bool                `api:"dry_run,optional"`
}

type rulesAutomationReplaceIn struct {
	ID              string              `api:"id,path"`
	Automation      rulesAutomationSpec `api:"automation"`
	ExpectedVersion string              `api:"expected_version,optional"`
	DryRun          bool                `api:"dry_run,optional"`
}

type rulesAutomationDeleteIn struct {
	ID              string `api:"id,path"`
	ExpectedVersion string `api:"expected_version,query,optional"`
}

// specFromAutomation は保存してある自動のルールを API の形にする（ポリシー・グループは ID）。
func specFromAutomation(a core.Automation) rulesAutomationSpec {
	j := toAutomationJSON(a)
	sp := rulesAutomationSpec{Name: j.Name, Disabled: !j.Enabled, Priority: j.Priority, Groups: j.GroupIDs, Trigger: string(j.Trigger),
		Windows: []rulesWindow{}, TimeZone: j.TimeZone, Reasons: j.Reasons, Policy: j.PolicyID}
	for _, w := range j.Windows {
		sp.Windows = append(sp.Windows, rulesWindow{Days: nonNil(w.Days), Start: w.Start, End: w.End})
	}
	return sp
}

func automationSpecJSON(sp rulesAutomationSpec) map[string]any {
	return map[string]any{"name": sp.Name, "disabled": sp.Disabled, "priority": sp.Priority, "groups": nonNil(sp.Groups),
		"trigger": sp.Trigger, "windows": sp.Windows, "time_zone": sp.TimeZone, "reasons": nonNil(sp.Reasons), "policy": sp.Policy}
}

// automationVersion は自動のルールの中身（時刻を除く）から決まる版。
func automationVersion(a core.Automation) string {
	b, _ := json.Marshal(automationSpecJSON(specFromAutomation(a)))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func toRulesAutomation(a core.Automation) rulesAutomation {
	return rulesAutomation{ID: a.ID, OrgID: a.OrgID, Version: automationVersion(a), Automation: specFromAutomation(a), UpdatedAt: a.UpdatedAt}
}

// resolvePolicy はポリシーの ID か名前を、組織 orgID から使えるポリシーの ID にする。
func (s *Server) resolvePolicy(ctx context.Context, orgID, ref string) (string, error) {
	if ref == "" {
		return "", bad("policy が要る（当たっているあいだ使うポリシーの ID か名前）")
	}
	ps, err := s.Store.ListPolicies(ctx)
	if err != nil {
		return "", err
	}
	var named []string
	for _, p := range ps {
		if p.OrgID != "" && p.OrgID != orgID {
			continue
		}
		if p.ID == ref {
			return p.ID, nil
		}
		if p.Name == ref {
			named = append(named, p.ID)
		}
	}
	switch len(named) {
	case 1:
		return named[0], nil
	case 0:
		return "", bad("policy %q のポリシーがこの組織に無い", ref)
	}
	return "", bad("名前 %q のポリシーが %d つある。ID を書く", ref, len(named))
}

// resolveGroups はグループの ID か名前を、組織 orgID のグループの ID にする。
func (s *Server) resolveGroups(ctx context.Context, orgID string, refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	gs, err := s.Store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		var named []string
		id := ""
		for _, g := range gs {
			if g.OrgID != orgID {
				continue
			}
			if g.ID == ref {
				id = g.ID
				break
			}
			if g.Name == ref {
				named = append(named, g.ID)
			}
		}
		switch {
		case id != "":
		case len(named) == 1:
			id = named[0]
		case len(named) == 0:
			return nil, bad("groups の %q のグループがこの組織に無い", ref)
		default:
			return nil, bad("名前 %q のグループが %d つある。ID を書く", ref, len(named))
		}
		out = append(out, id)
	}
	return out, nil
}

// toAutomation は管理の API と同じ確かめで、a（ID・組織・作った時刻を持つ）に sp を入れる。
func (s *Server) toAutomation(ctx context.Context, sp rulesAutomationSpec, a core.Automation) (core.Automation, error) {
	pid, err := s.resolvePolicy(ctx, a.OrgID, sp.Policy)
	if err != nil {
		return a, err
	}
	gids, err := s.resolveGroups(ctx, a.OrgID, sp.Groups)
	if err != nil {
		return a, err
	}
	enabled := !sp.Disabled
	in := automationInput{Name: sp.Name, Enabled: &enabled, Priority: sp.Priority, GroupIDs: gids, Trigger: core.AutomationTrigger(sp.Trigger),
		TimeZone: sp.TimeZone, Reasons: sp.Reasons, PolicyID: pid}
	for _, w := range sp.Windows {
		in.Windows = append(in.Windows, windowJSON(w))
	}
	if err := in.apply(&a); err != nil {
		return a, err
	}
	return a, nil
}

func (s *Server) rulesAutomationOps(a *rulesAuth, expose, read, write define.Option) []define.Operation {
	list := define.Query[rulesOrgIn, []rulesAutomation]("rules.automations.list",
		define.Doc("組織の自動のルールの一覧（条件に当たっているあいだ、端末に別のポリシーを使わせる）"),
		define.Authz("rules:read", define.Resource("org", "org_id")),
		define.HTTP("GET /v1/orgs/{org_id}/automations"), expose, read,
	).Handle(func(ctx context.Context, in rulesOrgIn) ([]rulesAutomation, error) {
		as, err := s.Store.ListAutomations(ctx)
		if err != nil {
			return nil, err
		}
		out := []rulesAutomation{}
		for _, x := range as {
			if x.OrgID == in.OrgID {
				out = append(out, toRulesAutomation(x))
			}
		}
		return out, nil
	})

	create := define.Command[rulesAutomationCreateIn, rulesAutomationResult]("rules.automations.create",
		define.Doc("組織に自動のルールを作る。dry_run なら作らずに中身だけ返す"),
		define.Authz("rules:write", define.Resource("org", "org_id")),
		define.HTTP("POST /v1/orgs/{org_id}/automations"), expose, write,
	).Handle(func(ctx context.Context, in rulesAutomationCreateIn) (rulesAutomationResult, error) {
		if _, err := s.Store.GetOrg(ctx, in.OrgID); err != nil {
			return rulesAutomationResult{}, storeErr(err)
		}
		now := s.Clock.Now()
		au, err := s.toAutomation(ctx, in.Automation, core.Automation{ID: core.NewID("aut"), OrgID: in.OrgID, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			return rulesAutomationResult{}, inputErr(err)
		}
		res := rulesAutomationResult{Automation: toRulesAutomation(au),
			Changes: diffFlat(automationSpecJSON(rulesAutomationSpec{}), automationSpecJSON(specFromAutomation(au)))}
		if in.DryRun {
			return res, nil
		}
		if err := s.saveAutomation(ctx, a.actor(ctx), au, true); err != nil {
			return rulesAutomationResult{}, inputErr(err)
		}
		res.Applied = true
		return res, nil
	})

	checkVersion := func(cur core.Automation, expected string) error {
		if expected != "" && expected != automationVersion(cur) {
			return define.Errorf(define.CodeFailedPrecondition, "自動のルールが先に変えられている（今の版 %s）。読み直してからやり直す", automationVersion(cur))
		}
		return nil
	}

	replace := define.Command[rulesAutomationReplaceIn, rulesAutomationResult]("rules.automations.replace",
		define.Doc("自動のルールを丸ごと置き換える（IaC の apply）。書かない項目は空になる。変わらなければ何もしない"),
		define.Authz("rules:write", define.Resource("automation", "id")),
		define.HTTP("PUT /v1/automations/{id}"), expose, write,
	).Handle(func(ctx context.Context, in rulesAutomationReplaceIn) (rulesAutomationResult, error) {
		automationMu.Lock()
		defer automationMu.Unlock()
		cur, err := s.Store.GetAutomation(ctx, in.ID)
		if err != nil {
			return rulesAutomationResult{}, storeErr(err)
		}
		if err := checkVersion(cur, in.ExpectedVersion); err != nil {
			return rulesAutomationResult{}, err
		}
		next, err := s.toAutomation(ctx, in.Automation, cur)
		if err != nil {
			return rulesAutomationResult{}, inputErr(err)
		}
		changes := diffFlat(automationSpecJSON(specFromAutomation(cur)), automationSpecJSON(specFromAutomation(next)))
		if len(changes) == 0 {
			return rulesAutomationResult{Automation: toRulesAutomation(cur), Changes: changes}, nil
		}
		next.UpdatedAt = s.Clock.Now()
		res := rulesAutomationResult{Automation: toRulesAutomation(next), Changes: changes}
		if in.DryRun {
			return res, nil
		}
		if err := s.saveAutomation(ctx, a.actor(ctx), next, false); err != nil {
			return rulesAutomationResult{}, inputErr(err)
		}
		res.Applied = true
		return res, nil
	})

	del := define.Command[rulesAutomationDeleteIn, rulesAutomation]("rules.automations.delete",
		define.Doc("自動のルールを消す（消したものを返す）。当たっていた端末は元のポリシーに戻る"),
		define.Authz("rules:write", define.Resource("automation", "id")),
		define.HTTP("DELETE /v1/automations/{id}"), expose, write,
	).Handle(func(ctx context.Context, in rulesAutomationDeleteIn) (rulesAutomation, error) {
		automationMu.Lock()
		defer automationMu.Unlock()
		cur, err := s.Store.GetAutomation(ctx, in.ID)
		if err != nil {
			return rulesAutomation{}, storeErr(err)
		}
		if err := checkVersion(cur, in.ExpectedVersion); err != nil {
			return rulesAutomation{}, err
		}
		if err := s.Store.DeleteAutomation(ctx, cur.ID); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return rulesAutomation{}, storeErr(err)
			}
			return rulesAutomation{}, err
		}
		s.changedAs(ctx, a.actor(ctx), cur.OrgID, "automation.delete", cur.ID)
		return toRulesAutomation(cur), nil
	})

	return []define.Operation{list, create, replace, del}
}
