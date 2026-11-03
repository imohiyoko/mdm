package filter

import (
	"context"
	"fmt"
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
	byHash   map[string]core.Device
	people   map[string]core.Person
	policies map[string]*compiledPolicy
	lists    map[string]DomainSet
	loadedAt time.Time
}

// Engine は保存先の内容をまとめて読み込み、問い合わせごとに判定する。
// 管理の変更のあとは Invalidate を呼ぶ。呼び忘れても MaxAge で読み直す。
type Engine struct {
	Store       core.Store
	Clock       core.Clock
	AlwaysAllow DomainSet
	MaxAge      time.Duration

	mu    sync.Mutex
	snap  *snapshot
	dirty bool
}

// Invalidate は次の判定の前に読み直させる。
func (e *Engine) Invalidate() {
	e.mu.Lock()
	e.dirty = true
	e.mu.Unlock()
}

func (e *Engine) load(ctx context.Context) (*snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Clock.Now()
	maxAge := e.MaxAge
	if maxAge == 0 {
		maxAge = time.Minute
	}
	if e.snap != nil && !e.dirty && now.Sub(e.snap.loadedAt) < maxAge {
		return e.snap, nil
	}
	s := &snapshot{
		byHash:   map[string]core.Device{},
		people:   map[string]core.Person{},
		policies: map[string]*compiledPolicy{},
		lists:    map[string]DomainSet{},
		loadedAt: now,
	}
	devices, err := e.Store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		s.byHash[string(d.FilterTokenHash)] = d
	}
	people, err := e.Store.ListPeople(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		s.people[p.ID] = p
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
	for id := range used {
		ds, err := e.Store.BlocklistDomains(ctx, id)
		if err != nil && err != core.ErrNotFound {
			return nil, err
		}
		s.lists[id] = NewDomainSet(ds)
	}
	e.snap, e.dirty = s, false
	return s, nil
}

// Device は秘密から端末を引く。見つからなければ core.ErrNotFound。
func (e *Engine) Device(ctx context.Context, token string) (core.Device, error) {
	if !core.LooksLikeFilterToken(token) {
		return core.Device{}, core.ErrNotFound
	}
	s, err := e.load(ctx)
	if err != nil {
		return core.Device{}, err
	}
	d, ok := s.byHash[string(core.HashFilterToken(token))]
	if !ok {
		return core.Device{}, core.ErrNotFound
	}
	return d, nil
}

func (s *snapshot) policyFor(d core.Device) *compiledPolicy {
	if p, ok := s.policies[d.PolicyID]; ok && d.PolicyID != "" {
		return p
	}
	if person, ok := s.people[d.PersonID]; ok && person.PolicyID != "" {
		if p, ok := s.policies[person.PolicyID]; ok {
			return p
		}
	}
	return s.policies[DefaultPolicyID]
}

// PolicyFor は端末に効いているポリシー（端末 → 持ち主 → 既定 の順）。
func (e *Engine) PolicyFor(ctx context.Context, d core.Device) (core.Policy, bool, error) {
	s, err := e.load(ctx)
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
	s, err := e.load(ctx)
	if err != nil {
		return Decision{}, core.Policy{}, err
	}
	n := Normalize(name)
	if n == "" {
		// ルートや壊れた名前は、上流に判断を任せる。
		return Decision{Action: core.ActionAllow, Reason: ReasonDefault}, core.Policy{}, nil
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
