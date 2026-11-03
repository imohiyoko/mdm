// Package compliance は端末が会社などのルールに沿っているか（準拠）を判定し、変わったら IAM に知らせる。
package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/ssf"
)

// 準拠していない理由。
const (
	ReasonNotManaged       = "not_managed"        // MDM で管理していない（登録していない・外れた・止められた）
	ReasonPolicyNotApplied = "policy_not_applied" // ポリシーを受け入れていない（まだ届いていない・端末が断った）
	ReasonNotEncrypted     = "not_encrypted"
	ReasonNoScreenLock     = "no_screen_lock"
	ReasonOSOutdated       = "os_outdated"
	ReasonNotReporting     = "not_reporting" // 決めた時間より長く端末から報告が無い
)

// Evaluate は端末の準拠しない理由を返す（空なら準拠）。m は管理の状態（無ければ nil）。
func Evaluate(r core.ComplianceRules, d core.Device, m *core.Managed, now time.Time) []string {
	if m == nil || m.State != core.ManagedActive {
		return []string{ReasonNotManaged}
	}
	var out []string
	if !m.PolicyCompliant {
		out = append(out, ReasonPolicyNotApplied)
	}
	if r.RequireEncryption && !m.Encrypted {
		out = append(out, ReasonNotEncrypted)
	}
	if r.RequireScreenLock && !m.ScreenLock {
		out = append(out, ReasonNoScreenLock)
	}
	if v := r.MinOSVersion[d.Platform]; v != "" && CompareVersions(m.OSVersion, v) < 0 {
		out = append(out, ReasonOSOutdated)
	}
	if r.MaxReportAgeHours > 0 && now.Sub(m.ReportedAt) > time.Duration(r.MaxReportAgeHours)*time.Hour {
		out = append(out, ReasonNotReporting)
	}
	return out
}

// CompareVersions は "17.4.1" のような版を数で比べる（a<b なら負）。読めない版（空など）は一番古いとみなす。
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	if pa == nil || pb == nil {
		switch {
		case pa == nil && pb == nil:
			return 0
		case pa == nil:
			return -1
		default:
			return 1
		}
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		// 「14 (Build …)」のような後ろの文字は捨てる。
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return nil
		}
		out = append(out, n)
		if end < len(p) {
			break
		}
	}
	return out
}

// ValidVersion は MinOSVersion に書ける版か。
func ValidVersion(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, p := range strings.Split(v, ".") {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

// Service はすべての端末を判定し、変わったものを記録して IAM に知らせる。
type Service struct {
	Store       core.Store
	Engine      *filter.Engine
	Clock       core.Clock
	Transmitter *ssf.Transmitter // nil なら知らせない
	Logger      *slog.Logger

	once sync.Once
	kick chan struct{}
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// EvaluateAll はすべての端末を判定する。
func (s *Service) EvaluateAll(ctx context.Context) error {
	ds, err := s.Store.ListDevices(ctx)
	if err != nil {
		return err
	}
	prev := map[string]core.DeviceCompliance{}
	cs, err := s.Store.ListCompliance(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		prev[c.DeviceID] = c
	}
	now := s.Clock.Now()
	var errs []error
	for _, d := range ds {
		if err := s.evaluate(ctx, d, prev, now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) evaluate(ctx context.Context, d core.Device, prev map[string]core.DeviceCompliance, now time.Time) error {
	// 自動のルールで切り替えたポリシーではなく、元のポリシーの条件で判定する（ADR 0017）。
	pol, _, err := s.Engine.BasePolicyFor(ctx, d)
	if err != nil {
		return err
	}
	var mp *core.Managed
	m, err := s.Store.GetManaged(ctx, d.ID)
	switch {
	case err == nil:
		mp = &m
	case !errors.Is(err, core.ErrNotFound):
		return err
	}
	reasons := Evaluate(pol.Compliance, d, mp, now)
	c := core.DeviceCompliance{DeviceID: d.ID, Compliant: len(reasons) == 0, Reasons: reasons, ChangedAt: now, EvaluatedAt: now}
	old, seen := prev[d.ID]
	if seen && old.Compliant == c.Compliant {
		c.ChangedAt = old.ChangedAt
		same := slices.Equal(old.Reasons, c.Reasons)
		if same && now.Sub(old.EvaluatedAt) < time.Hour {
			return nil // 書き込みを減らす（判定した時刻は 1 時間ごとに更新する）
		}
		if err := s.Store.PutCompliance(ctx, c); err != nil {
			return err
		}
		if !same {
			s.Engine.Invalidate() // 理由で決まる自動のルールのため
		}
		return nil
	}
	if err := s.Store.PutCompliance(ctx, c); err != nil {
		return err
	}
	s.Engine.Invalidate()
	return s.notify(ctx, d, c, old, seen)
}

func status(compliant bool) string {
	if compliant {
		return ssf.StatusCompliant
	}
	return ssf.StatusNotCompliant
}

// notify は変化を IAM に知らせる。持ち主がいてメールアドレスがあるときだけ。
func (s *Service) notify(ctx context.Context, d core.Device, c core.DeviceCompliance, old core.DeviceCompliance, seen bool) error {
	if !s.Transmitter.Enabled() || d.PersonID == "" {
		return nil
	}
	p, err := s.Store.GetPerson(ctx, d.PersonID)
	if err != nil || p.Email == "" {
		return err
	}
	ch := ssf.ComplianceChange{Email: p.Email, DeviceID: d.ID, OrgID: d.OrgID, Current: status(c.Compliant), ChangedAt: c.ChangedAt,
		Reason: strings.Join(c.Reasons, ", ")}
	if seen {
		ch.Previous = status(old.Compliant)
	}
	if err := s.Transmitter.Enqueue(ctx, ch); err != nil {
		return err
	}
	s.log().Info("compliance changed", "device", d.ID, "status", ch.Current, "reasons", ch.Reason)
	return nil
}

// Resend は端末の今の状態を、もう一度 IAM に知らせる（持ち主やメールアドレスが変わったとき）。
// まだ判定していない端末は、次の判定で知らせる。
func (s *Service) Resend(ctx context.Context, deviceIDs ...string) error {
	if !s.Transmitter.Enabled() {
		return nil
	}
	for _, id := range deviceIDs {
		c, err := s.Store.GetCompliance(ctx, id)
		if errors.Is(err, core.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		d, err := s.Store.GetDevice(ctx, id)
		if err != nil {
			return err
		}
		if err := s.notify(ctx, d, c, core.DeviceCompliance{}, false); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) kickCh() chan struct{} {
	s.once.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// Kick は判定し直しを頼む（すぐ戻る）。
func (s *Service) Kick() {
	select {
	case s.kickCh() <- struct{}{}:
	default:
	}
}

// Run は interval ごとと Kick されたときに判定し、送る待ちの SET を送る。
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.EvaluateAll(ctx); err != nil && ctx.Err() == nil {
			s.log().Error("compliance", "err", err)
		}
		if s.Transmitter.Enabled() {
			if err := s.Transmitter.DeliverDue(ctx); err != nil && ctx.Err() == nil {
				s.log().Error("ssf deliver", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kickCh():
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}
