package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/core"
)

// 自動のルール（ADR 0017）。条件に当たっているあいだ、端末に別のポリシーを使わせる。

// maxAutomations は 1 つの組織で作れる自動のルールの数。
const maxAutomations = 50

// automationReasons は noncompliant の reasons に書ける理由。
var automationReasons = []string{
	compliance.ReasonNotManaged, compliance.ReasonPolicyNotApplied, compliance.ReasonNotEncrypted,
	compliance.ReasonNoScreenLock, compliance.ReasonOSOutdated, compliance.ReasonNotReporting,
}

type automationJSON struct {
	ID        string                 `json:"id"`
	OrgID     string                 `json:"org_id"`
	Name      string                 `json:"name"`
	Enabled   bool                   `json:"enabled"`
	Priority  int                    `json:"priority"`
	GroupIDs  []string               `json:"group_ids"`
	Trigger   core.AutomationTrigger `json:"trigger"`
	Windows   []windowJSON           `json:"windows"`
	TimeZone  string                 `json:"time_zone,omitempty"`
	Reasons   []string               `json:"reasons"`
	PolicyID  string                 `json:"policy_id"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

func toAutomationJSON(a core.Automation) automationJSON {
	return automationJSON{
		ID: a.ID, OrgID: a.OrgID, Name: a.Name, Enabled: a.Enabled, Priority: a.Priority, GroupIDs: nonNil(a.GroupIDs),
		Trigger: a.Trigger, Windows: toWindowsJSON(a.Windows), TimeZone: a.TimeZone, Reasons: nonNil(a.Reasons),
		PolicyID: a.PolicyID, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
}

// automationInput は作る・置き換えるときの中身（置き換えは全体を送る）。
type automationInput struct {
	OrgID    string                 `json:"org_id"` // 作るときだけ
	Name     string                 `json:"name"`
	Enabled  *bool                  `json:"enabled"` // 省くと有効
	Priority int                    `json:"priority"`
	GroupIDs []string               `json:"group_ids"`
	Trigger  core.AutomationTrigger `json:"trigger"`
	Windows  []windowJSON           `json:"windows"`
	TimeZone string                 `json:"time_zone"`
	Reasons  []string               `json:"reasons"`
	PolicyID string                 `json:"policy_id"`
}

// apply は中身を確かめて a に入れる（参照するポリシー・グループは saveAutomation で確かめる）。
func (in automationInput) apply(a *core.Automation) error {
	a.Name = strings.TrimSpace(in.Name)
	if a.Name == "" || len(a.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	a.Enabled = in.Enabled == nil || *in.Enabled
	if in.Priority < -1000 || in.Priority > 1000 {
		return bad("priority は -1000〜1000")
	}
	a.Priority = in.Priority
	if len(in.GroupIDs) > 100 {
		return bad("group_ids は 100 件まで")
	}
	a.GroupIDs = slices.Compact(slices.Sorted(slices.Values(in.GroupIDs)))
	if in.PolicyID == "" {
		return bad("policy_id が要る（当たっているあいだ使うポリシー）")
	}
	a.PolicyID = in.PolicyID
	a.Trigger, a.Windows, a.TimeZone, a.Reasons = in.Trigger, nil, "", nil
	switch in.Trigger {
	case core.TriggerSchedule:
		if len(in.Reasons) > 0 {
			return bad("reasons は trigger が noncompliant のときだけ")
		}
		if len(in.Windows) == 0 {
			return bad("trigger が schedule なら windows が要る")
		}
		var err error
		if a.Windows, err = parseWindows("windows", in.Windows); err != nil {
			return err
		}
		if in.TimeZone != "" {
			if _, err := time.LoadLocation(in.TimeZone); err != nil {
				return bad("time_zone が分からない（%q）", in.TimeZone)
			}
		}
		a.TimeZone = in.TimeZone
	case core.TriggerNoncompliant:
		if len(in.Windows) > 0 || in.TimeZone != "" {
			return bad("windows・time_zone は trigger が schedule のときだけ")
		}
		if len(in.Reasons) == 0 {
			return bad("trigger が noncompliant なら reasons が要る（%s）", strings.Join(automationReasons, "・"))
		}
		for _, r := range in.Reasons {
			if !slices.Contains(automationReasons, r) {
				return bad("reasons は %s のどれか（%q）", strings.Join(automationReasons, "・"), r)
			}
		}
		a.Reasons = slices.Compact(slices.Sorted(slices.Values(in.Reasons)))
	default:
		return bad("trigger は schedule か noncompliant")
	}
	return nil
}

// saveAutomation は参照を確かめて作る（create）か置き換え、記録して配り直す。
func (s *Server) saveAutomation(ctx context.Context, actor string, a core.Automation, create bool) error {
	if err := s.policyInOrg(ctx, a.PolicyID, a.OrgID); err != nil {
		return err
	}
	if err := s.groupsInOrg(ctx, a.GroupIDs, a.OrgID); err != nil {
		return err
	}
	if create {
		if err := s.createAutomationLimited(ctx, a); err != nil {
			return err
		}
		s.changedAs(ctx, actor, a.OrgID, "automation.create", a.ID)
		return nil
	}
	if err := s.Store.UpdateAutomation(ctx, a); err != nil {
		return err
	}
	s.changedAs(ctx, actor, a.OrgID, "automation.update", a.ID)
	return nil
}

// createAutomationLimited は組織の上限を確かめて作る（数えてから作るまで、ほかの作成を割り込ませない）。
func (s *Server) createAutomationLimited(ctx context.Context, a core.Automation) error {
	quotaMu.Lock()
	defer quotaMu.Unlock()
	all, err := s.Store.ListAutomations(ctx)
	if err != nil {
		return err
	}
	n := 0
	for _, x := range all {
		if x.OrgID == a.OrgID {
			n++
		}
	}
	if n >= maxAutomations {
		return quotaError{fmt.Sprintf("この組織で作れる自動のルールは %d まで", maxAutomations)}
	}
	return s.Store.CreateAutomation(ctx, a)
}

func writeAutomationErr(w http.ResponseWriter, err error) {
	if _, ok := err.(quotaError); ok {
		writeReserveErr(w, err)
		return
	}
	handleInputErr(w, err)
}

func (s *Server) listAutomations(w http.ResponseWriter, r *http.Request) {
	as, err := s.Store.ListAutomations(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p, org := principal(r.Context()), r.URL.Query().Get("org_id")
	out := []automationJSON{}
	for _, a := range as {
		if p.CanRead(a.OrgID) && (org == "" || a.OrgID == org) {
			out = append(out, toAutomationJSON(a))
		}
	}
	writeJSON(w, 200, map[string]any{"automations": out})
}

func (s *Server) createAutomation(w http.ResponseWriter, r *http.Request) {
	var in automationInput
	if !readJSON(w, r, &in) {
		return
	}
	org, ok := s.targetOrg(w, r, &in.OrgID)
	if !ok {
		return
	}
	now := s.Clock.Now()
	a := core.Automation{ID: core.NewID("aut"), OrgID: org, CreatedAt: now, UpdatedAt: now}
	err := in.apply(&a)
	if err == nil {
		err = s.saveAutomation(r.Context(), principal(r.Context()).Name, a, true)
	}
	if err != nil {
		writeAutomationErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAutomationJSON(a))
}

func (s *Server) loadAutomation(w http.ResponseWriter, r *http.Request, write bool) (core.Automation, bool) {
	a, err := s.Store.GetAutomation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return a, false
	}
	if write {
		return a, canWrite(w, r, a.OrgID)
	}
	return a, canRead(w, r, a.OrgID)
}

func (s *Server) getAutomation(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.loadAutomation(w, r, false); ok {
		writeJSON(w, 200, toAutomationJSON(a))
	}
}

func (s *Server) putAutomation(w http.ResponseWriter, r *http.Request) {
	var in automationInput
	if !readJSON(w, r, &in) {
		return
	}
	a, ok := s.loadAutomation(w, r, true)
	if !ok {
		return
	}
	if in.OrgID != "" && in.OrgID != a.OrgID {
		writeErr(w, 400, "invalid_request", "org_id は変えられない")
		return
	}
	a.UpdatedAt = s.Clock.Now()
	err := in.apply(&a)
	if err == nil {
		err = s.saveAutomation(r.Context(), principal(r.Context()).Name, a, false)
	}
	if err != nil {
		writeAutomationErr(w, err)
		return
	}
	writeJSON(w, 200, toAutomationJSON(a))
}

func (s *Server) deleteAutomation(w http.ResponseWriter, r *http.Request) {
	a, ok := s.loadAutomation(w, r, true)
	if !ok {
		return
	}
	if err := s.Store.DeleteAutomation(r.Context(), a.ID); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, a.OrgID, "automation.delete", a.ID)
	w.WriteHeader(http.StatusNoContent)
}
