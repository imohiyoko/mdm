package filter

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// DefaultPolicyID は、端末にも持ち主にもポリシーが無いときに使うポリシー。起動時に無ければ作る。
const DefaultPolicyID = "default"

// Reason は判定の理由。記録と管理画面に出す。
type Reason string

const (
	ReasonAlwaysAllowed Reason = "always_allowed" // 運用者が止めないと決めた通信（端末の管理に要るもの）
	ReasonAllowed       Reason = "allowed"        // ポリシーの許可の一覧
	ReasonPaused        Reason = "paused"         // 「今すぐ止める」
	ReasonQuietHours    Reason = "quiet_hours"    // 止める時間帯
	ReasonNotAllowed    Reason = "not_allowed"    // 許可の一覧だけを通すポリシーで、一覧に無い
	ReasonBlocked       Reason = "blocked"        // ポリシーのブロックの一覧
	ReasonBlocklist     Reason = "blocklist"      // 取り込んだ外部の一覧
	ReasonInvalidName   Reason = "invalid_name"   // 読めない名前（使えない文字・長すぎる）
	ReasonDefault       Reason = "default"        // どれにも当たらない
)

// Decision は判定の結果。
type Decision struct {
	Action  core.Action
	Reason  Reason
	Matched string // 当たったドメインや一覧の ID
}

type compiledPolicy struct {
	core.Policy
	allow, block DomainSet
	loc          *time.Location
}

type snapshot struct {
	byHash   map[string]core.Device // DoH の秘密のハッシュ → 端末
	byDoT    map[string]core.Device // DoT のラベルのハッシュ → 端末
	people   map[string]core.Person
	groups   map[string]core.Group
	orgs     map[string]core.Org
	policies map[string]*compiledPolicy
	lists    map[string]DomainSet
	listAt   map[string]time.Time // 一覧を取り込んだ時刻。変わっていなければ作り直さない
	loadedAt time.Time
}

// Engine は保存先の内容をまとめて読み込み（スナップショット）、問い合わせごとに判定する。
//
// 問い合わせは読み込みを待たない。古くなったら後ろで読み直し、その間と、読み直しに失敗したときは
// 前のスナップショットで判定する（保存先の一時的な失敗で家じゅうの通信を止めない）。
// 管理の変更のあとは Refresh を呼ぶと、次の問い合わせから新しい内容で判定する。
type Engine struct {
	Store       core.Store
	Clock       core.Clock
	AlwaysAllow DomainSet
	MaxAge      time.Duration // 既定 1 分
	Logger      *slog.Logger

	buildMu sync.Mutex // 読み込みを 1 つずつにする

	mu       sync.Mutex
	snap     *snapshot
	dirty    bool
	retryAt  time.Time // 失敗のあと、この時刻までは読み直さない
	building bool
}

const retryDelay = 5 * time.Second

// Invalidate は後ろで読み直させる。
func (e *Engine) Invalidate() {
	e.mu.Lock()
	e.dirty = true
	e.retryAt = time.Time{}
	e.mu.Unlock()
}

// Refresh はいま読み直す。終わるまで戻らない（管理の API から呼ぶ）。
func (e *Engine) Refresh(ctx context.Context) error {
	e.mu.Lock()
	e.dirty = true
	e.mu.Unlock()
	_, err := e.rebuild(ctx)
	return err
}

func (e *Engine) maxAge() time.Duration {
	if e.MaxAge == 0 {
		return time.Minute
	}
	return e.MaxAge
}

// current は判定に使うスナップショット。まだ一度も読んでいなければ読む。
func (e *Engine) current(ctx context.Context) (*snapshot, error) {
	e.mu.Lock()
	s := e.snap
	now := e.Clock.Now()
	stale := s == nil || ((e.dirty || now.Sub(s.loadedAt) >= e.maxAge()) && !now.Before(e.retryAt))
	if !stale || (s != nil && e.building) {
		e.mu.Unlock()
		return s, nil
	}
	if s != nil {
		e.building = true
		e.mu.Unlock()
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_, _ = e.rebuild(ctx)
		}()
		return s, nil
	}
	e.mu.Unlock()
	return e.rebuild(ctx)
}

// rebuild は読み込んで入れ替える。失敗したら前のスナップショットを残す。
func (e *Engine) rebuild(ctx context.Context) (*snapshot, error) {
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	e.mu.Lock()
	prev := e.snap
	e.dirty = false // 読み込みの間に変わったら、もう一度立つ
	e.mu.Unlock()

	s, err := e.build(ctx, prev)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.building = false
	if err != nil {
		e.dirty = true
		e.retryAt = e.Clock.Now().Add(retryDelay)
		if e.Logger != nil {
			e.Logger.Error("filter reload", "err", err)
		}
		if prev != nil {
			return prev, err
		}
		return nil, err
	}
	e.snap, e.retryAt = s, time.Time{}
	return s, nil
}

func (e *Engine) build(ctx context.Context, prev *snapshot) (*snapshot, error) {
	s := &snapshot{
		byHash:   map[string]core.Device{},
		byDoT:    map[string]core.Device{},
		people:   map[string]core.Person{},
		groups:   map[string]core.Group{},
		orgs:     map[string]core.Org{},
		policies: map[string]*compiledPolicy{},
		lists:    map[string]DomainSet{},
		listAt:   map[string]time.Time{},
		loadedAt: e.Clock.Now(),
	}
	devices, err := e.Store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		s.byHash[string(d.FilterTokenHash)] = d
		s.byDoT[string(d.DoTLabelHash)] = d
	}
	people, err := e.Store.ListPeople(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		s.people[p.ID] = p
	}
	groups, err := e.Store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		s.groups[g.ID] = g
	}
	orgs, err := e.Store.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		s.orgs[o.ID] = o
	}
	policies, err := e.Store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, p := range policies {
		loc := time.UTC
		if p.TimeZone != "" {
			if l, err := time.LoadLocation(p.TimeZone); err == nil {
				loc = l
			}
		}
		s.policies[p.ID] = &compiledPolicy{Policy: p, allow: NewDomainSet(p.Allow), block: NewDomainSet(p.Block), loc: loc}
		for _, id := range p.ListIDs {
			used[id] = true
		}
	}
	if len(used) > 0 {
		lists, err := e.Store.ListBlocklists(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range lists {
			if !used[b.ID] {
				continue
			}
			s.listAt[b.ID] = b.RefreshedAt
			if prev != nil {
				if at, ok := prev.listAt[b.ID]; ok && at.Equal(b.RefreshedAt) {
					s.lists[b.ID] = prev.lists[b.ID]
					continue
				}
			}
			ds, err := e.Store.BlocklistDomains(ctx, b.ID)
			if err != nil {
				return nil, err
			}
			s.lists[b.ID] = NewDomainSet(ds)
		}
	}
	return s, nil
}

// Device は DoH の秘密から端末を引く。見つからなければ core.ErrNotFound。
func (e *Engine) Device(ctx context.Context, token string) (core.Device, error) {
	return e.lookup(ctx, token, func(s *snapshot) map[string]core.Device { return s.byHash })
}

// DeviceByDoTLabel は DoT のホスト名の先頭のラベルから端末を引く。
func (e *Engine) DeviceByDoTLabel(ctx context.Context, label string) (core.Device, error) {
	return e.lookup(ctx, label, func(s *snapshot) map[string]core.Device { return s.byDoT })
}

func (e *Engine) lookup(ctx context.Context, token string, index func(*snapshot) map[string]core.Device) (core.Device, error) {
	if !core.LooksLikeFilterToken(token) {
		return core.Device{}, core.ErrNotFound
	}
	s, err := e.current(ctx)
	if err != nil {
		return core.Device{}, err
	}
	d, ok := index(s)[string(core.HashFilterToken(token))]
	if !ok {
		return core.Device{}, core.ErrNotFound
	}
	return d, nil
}

// usable は、組織 orgID の端末にポリシー id を使えるか（ほかの組織のポリシーは使わない）。
func (s *snapshot) usable(id, orgID string) *compiledPolicy {
	if id == "" {
		return nil
	}
	p, ok := s.policies[id]
	if !ok || (p.OrgID != "" && p.OrgID != orgID) {
		return nil
	}
	return p
}

// policyFor は端末に効くポリシー：端末 → 持ち主 → 持ち主のグループ（優先度の高い順）→ 組織の既定 → サーバー全体の既定。
func (s *snapshot) policyFor(d core.Device) *compiledPolicy {
	if p := s.usable(d.PolicyID, d.OrgID); p != nil {
		return p
	}
	if person, ok := s.people[d.PersonID]; ok && person.OrgID == d.OrgID {
		if p := s.usable(person.PolicyID, d.OrgID); p != nil {
			return p
		}
		var best *core.Group
		for _, gid := range person.GroupIDs {
			g, ok := s.groups[gid]
			if !ok || g.OrgID != d.OrgID || s.usable(g.PolicyID, d.OrgID) == nil {
				continue
			}
			if best == nil || g.Priority > best.Priority || g.Priority == best.Priority && g.ID < best.ID {
				best = &g
			}
		}
		if best != nil {
			return s.usable(best.PolicyID, d.OrgID)
		}
	}
	if o, ok := s.orgs[d.OrgID]; ok {
		if p := s.usable(o.DefaultPolicyID, d.OrgID); p != nil {
			return p
		}
	}
	return s.policies[DefaultPolicyID]
}

// PolicyFor は端末に効いているポリシー（端末 → 持ち主 → 既定 の順）。
func (e *Engine) PolicyFor(ctx context.Context, d core.Device) (core.Policy, bool, error) {
	s, err := e.current(ctx)
	if err != nil {
		return core.Policy{}, false, err
	}
	p := s.policyFor(d)
	if p == nil {
		return core.Policy{}, false, nil
	}
	return p.Policy, true, nil
}

// Decide は端末 d からの name の問い合わせを通すか決める。
func (e *Engine) Decide(ctx context.Context, d core.Device, name string) (Decision, core.Policy, error) {
	s, err := e.current(ctx)
	if err != nil {
		return Decision{}, core.Policy{}, err
	}
	n := Normalize(name)
	if n == "" {
		if name == "." || name == "" {
			// ルートは上流に任せる。
			return Decision{Action: core.ActionAllow, Reason: ReasonDefault}, core.Policy{}, nil
		}
		// 読めない名前は通さない（今すぐ止める・許可の一覧だけ を抜けさせない）。
		return Decision{Action: core.ActionBlock, Reason: ReasonInvalidName}, core.Policy{}, nil
	}
	if m, ok := e.AlwaysAllow.Match(n); ok {
		return Decision{core.ActionAllow, ReasonAlwaysAllowed, m}, core.Policy{}, nil
	}
	p := s.policyFor(d)
	if p == nil {
		// 既定のポリシーが消えていても、通信を止めて端末を使えなくはしない。
		return Decision{Action: core.ActionAllow, Reason: ReasonDefault}, core.Policy{}, nil
	}
	if m, ok := p.allow.Match(n); ok {
		return Decision{core.ActionAllow, ReasonAllowed, m}, p.Policy, nil
	}
	now := e.Clock.Now()
	if now.Before(d.PausedUntil) {
		return Decision{Action: core.ActionBlock, Reason: ReasonPaused}, p.Policy, nil
	}
	local := now.In(p.loc)
	for i, w := range p.Quiet {
		if w.Contains(local) {
			return Decision{core.ActionBlock, ReasonQuietHours, fmt.Sprint(i)}, p.Policy, nil
		}
	}
	if p.Mode == core.FilterAllowlistOnly {
		return Decision{Action: core.ActionBlock, Reason: ReasonNotAllowed}, p.Policy, nil
	}
	if m, ok := p.block.Match(n); ok {
		return Decision{core.ActionBlock, ReasonBlocked, m}, p.Policy, nil
	}
	for _, id := range p.ListIDs {
		if _, ok := s.lists[id].Match(n); ok {
			return Decision{core.ActionBlock, ReasonBlocklist, id}, p.Policy, nil
		}
	}
	return Decision{Action: core.ActionAllow, Reason: ReasonDefault}, p.Policy, nil
}
