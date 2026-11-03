package adminapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// サインアップ：IAM でログインした人が自分の組織を作り、その組織の管理者になる。
// 招待：組織の管理者がコードを作って渡し、受け取った人が IAM でログインしてコードを出すと、その組織の管理者になる。
// 招待は IAM のユーザーの id（sub）を知らなくても管理者を増やせるようにするもの。コードを持っている人なら誰でも受けられるので、
// 本人にだけ渡す。

// Signup はサインアップの設定。
type Signup struct {
	Enabled bool
	// MaxOrgsPerUser は 1 人が自分で作れる組織の数。0 なら 3。
	MaxOrgsPerUser int
}

const (
	defaultMaxOrgsPerUser = 3
	invitationTTL         = 7 * 24 * time.Hour
	maxInvitationsPerOrg  = 50
	invitationPrefix      = "mdminv_"
)

var signupMu sync.Mutex // 数えてから作るまでのあいだに、同じ人の作成を割り込ませない

// iamUser は IAM でログインした人か。設定の鍵ではサインアップ・招待を受けることはできない（誰なのかが IAM に無い）。
func iamUser(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p := principal(r.Context())
	if p.Subject == "" {
		writeErr(w, http.StatusForbidden, "forbidden", "IAM でログインした人だけができる")
		return nil, false
	}
	return p, true
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	if !s.Signup.Enabled {
		writeErr(w, http.StatusForbidden, "signup_disabled", "このサーバーでは自分で組織を作れない（サーバーの管理者に頼む）")
		return
	}
	p, ok := iamUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Name string       `json:"name"`
		Kind core.OrgKind `json:"kind"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Kind == "" {
		in.Kind = core.OrgFamily
	}
	now := s.Clock.Now()
	o := core.Org{ID: core.NewID("org"), CreatedAt: now}
	if err := (orgInput{Name: &in.Name, Kind: &in.Kind}).apply(&o); err != nil {
		handleInputErr(w, err)
		return
	}
	max := s.Signup.MaxOrgsPerUser
	if max <= 0 {
		max = defaultMaxOrgsPerUser
	}
	signupMu.Lock()
	defer signupMu.Unlock()
	n, err := s.Store.CountSignups(r.Context(), p.Issuer, p.Subject)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if n >= max {
		writeErr(w, http.StatusConflict, "limit_exceeded", fmt.Sprintf("自分で作れる組織は %d まで", max))
		return
	}
	b := core.AdminBinding{ID: core.NewID("adm"), Issuer: p.Issuer, Subject: p.Subject, Label: p.Name, Role: core.AdminOrg, OrgID: o.ID, CreatedAt: now}
	if err := s.Store.SignupOrg(r.Context(), o, b); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, o.ID, "org.signup", o.ID)
	writeJSON(w, http.StatusCreated, toOrgJSON(o))
}

type invitationJSON struct {
	ID        string         `json:"id"`
	OrgID     string         `json:"org_id"`
	Role      core.AdminRole `json:"role"`
	Label     string         `json:"label,omitempty"`
	CreatedBy string         `json:"created_by"`
	ExpiresAt time.Time      `json:"expires_at"`
	CreatedAt time.Time      `json:"created_at"`
	// Code は作ったときだけ返す。
	Code string `json:"code,omitempty"`
}

func toInvitationJSON(i core.Invitation) invitationJSON {
	return invitationJSON{ID: i.ID, OrgID: i.OrgID, Role: i.Role, Label: i.Label, CreatedBy: i.CreatedBy, ExpiresAt: i.ExpiresAt, CreatedAt: i.CreatedAt}
}

func invitationHash(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) {
		return
	}
	is, err := s.Store.ListInvitations(r.Context(), org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	now := s.Clock.Now()
	out := []invitationJSON{}
	for _, i := range is {
		if now.Before(i.ExpiresAt) {
			out = append(out, toInvitationJSON(i))
		}
	}
	writeJSON(w, 200, map[string]any{"invitations": out})
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	org, ok := s.targetOrg(w, r, &id)
	if !ok {
		return
	}
	var in struct {
		Role  core.AdminRole `json:"role"`
		Label string         `json:"label"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Role == "" {
		in.Role = core.AdminOrg
	}
	in.Label = strings.TrimSpace(in.Label)
	switch {
	case in.Role != core.AdminOrg && in.Role != core.AdminOrgViewer:
		writeErr(w, 400, "invalid_request", "role は org_admin か org_viewer")
		return
	case len(in.Label) > 255:
		writeErr(w, 400, "invalid_request", "label は 255 文字まで")
		return
	}
	now := s.Clock.Now()
	if err := s.Store.DeleteExpiredInvitations(r.Context(), now); err != nil {
		writeStoreErr(w, err)
		return
	}
	is, err := s.Store.ListInvitations(r.Context(), org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if len(is) >= maxInvitationsPerOrg {
		writeErr(w, http.StatusConflict, "limit_exceeded", fmt.Sprintf("まだ受けられていない招待は 1 組織 %d まで（古いものを消す）", maxInvitationsPerOrg))
		return
	}
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	code := invitationPrefix + base64.RawURLEncoding.EncodeToString(buf)
	inv := core.Invitation{ID: core.NewID("inv"), OrgID: org, Role: in.Role, Label: in.Label, CodeHash: invitationHash(code),
		CreatedBy: principal(r.Context()).Name, ExpiresAt: now.Add(invitationTTL), CreatedAt: now}
	if err := s.Store.CreateInvitation(r.Context(), inv); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "invitation.create", inv.ID)
	out := toInvitationJSON(inv)
	out.Code = code
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) deleteInvitation(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) {
		return
	}
	id := r.PathValue("iid")
	if err := s.Store.DeleteInvitation(r.Context(), org, id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "invitation.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	p, ok := iamUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Code = strings.TrimSpace(in.Code)
	if !strings.HasPrefix(in.Code, invitationPrefix) {
		writeErr(w, 400, "invalid_request", "code は招待のコード（mdminv_ で始まる）")
		return
	}
	b := core.AdminBinding{ID: core.NewID("adm"), Issuer: p.Issuer, Subject: p.Subject, Label: p.Name, CreatedAt: s.Clock.Now()}
	b, err := s.Store.AcceptInvitation(r.Context(), invitationHash(in.Code), s.Clock.Now(), b)
	switch {
	case errors.Is(err, core.ErrNotFound):
		writeErr(w, http.StatusNotFound, "invalid_invitation", "招待が無いか、期限が切れているか、もう使われている")
		return
	case errors.Is(err, core.ErrConflict):
		writeErr(w, http.StatusConflict, "conflict", "すでにこの組織の管理者になっている")
		return
	case err != nil:
		writeStoreErr(w, err)
		return
	}
	s.audit(r, b.OrgID, "invitation.accept", b.ID)
	writeJSON(w, http.StatusCreated, toBindingJSON(b))
}
