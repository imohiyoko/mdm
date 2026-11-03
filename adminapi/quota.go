package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/imohiyoko/mdm/core"
)

// 組織ごとの上限（ADR 0013）。サーバーの設定に既定（Server.Limits）を書き、サーバーの管理者が組織ごとに変えられる。
// 組織の管理者は自分の組織の上限と使っている数を見られる。

var quotaMu sync.Mutex // 数えてから作るまでのあいだに、ほかの作成を割り込ませない

type limitKind int

const (
	limitDevices limitKind = iota
	limitPeople
	limitGroups
	limitPolicies
)

func (k limitKind) name() string {
	return [...]string{"端末", "人", "グループ", "ポリシー"}[k]
}

// limitsFor は組織の上限（組織ごとの値が無ければ設定の既定）。
func (s *Server) limitsFor(ctx context.Context, orgID string) (core.OrgLimits, bool, error) {
	l, err := s.Store.GetOrgLimits(ctx, orgID)
	if errors.Is(err, core.ErrNotFound) {
		return s.Limits, false, nil
	}
	return l, err == nil, err
}

type quotaError struct{ msg string }

func (e quotaError) Error() string { return e.msg }

// reserve は組織 orgID にもう 1 つ kind を作れるか確かめる。作れるなら quotaMu を持ったまま返すので、作ったあとに unlock を呼ぶ。
func (s *Server) reserve(ctx context.Context, orgID string, kind limitKind) (unlock func(), err error) {
	quotaMu.Lock()
	l, _, err := s.limitsFor(ctx, orgID)
	if err == nil {
		var u core.OrgUsage
		if u, err = s.Store.OrgUsage(ctx, orgID); err == nil {
			max, n := [...]int{l.Devices, l.People, l.Groups, l.Policies}[kind], [...]int{u.Devices, u.People, u.Groups, u.Policies}[kind]
			if max > 0 && n >= max {
				err = quotaError{fmt.Sprintf("この組織で作れる%sは %d まで", kind.name(), max)}
			}
		}
	}
	if err != nil {
		quotaMu.Unlock()
		return nil, err
	}
	return quotaMu.Unlock, nil
}

// writeReserveErr は reserve のエラーを返す（上限なら 409 limit_exceeded）。
func writeReserveErr(w http.ResponseWriter, err error) {
	var q quotaError
	if errors.As(err, &q) {
		writeErr(w, http.StatusConflict, "limit_exceeded", q.msg)
		return
	}
	writeStoreErr(w, err)
}

type limitsJSON struct {
	Devices  int `json:"devices"`
	People   int `json:"people"`
	Groups   int `json:"groups"`
	Policies int `json:"policies"`
}

func toLimitsJSON(l core.OrgLimits) limitsJSON {
	return limitsJSON{l.Devices, l.People, l.Groups, l.Policies}
}

// GET /v1/orgs/{id}/usage は組織の使っている数と上限。
func (s *Server) orgUsage(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canRead(w, r, org) {
		return
	}
	ctx := r.Context()
	if _, err := s.Store.GetOrg(ctx, org); err != nil {
		writeStoreErr(w, err)
		return
	}
	u, err := s.Store.OrgUsage(ctx, org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	l, custom, err := s.limitsFor(ctx, org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"usage": map[string]int{
			"devices": u.Devices, "people": u.People, "groups": u.Groups, "policies": u.Policies,
			"admins": u.Admins, "radius_clients": u.RADIUSClients, "ssf_receivers": u.SSFReceivers,
		},
		"limits":        toLimitsJSON(l),
		"custom_limits": custom,
		// 決まった上限（ここでは変えられない）。
		"fixed_limits": map[string]int{"radius_clients": maxRADIUSClientsPerOrg, "ssf_receivers": maxSSFReceiversPerOrg, "pending_invitations": maxInvitationsPerOrg},
	})
}

// PUT /v1/orgs/{id}/limits は組織の上限を決める（サーバー全体の管理者だけ）。0 は上限なし。
func (s *Server) putOrgLimits(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	org := r.PathValue("id")
	var in limitsJSON
	if !readJSON(w, r, &in) {
		return
	}
	if in.Devices < 0 || in.People < 0 || in.Groups < 0 || in.Policies < 0 {
		writeErr(w, 400, "invalid_request", "上限は 0 以上（0 は上限なし）")
		return
	}
	if _, err := s.Store.GetOrg(r.Context(), org); err != nil {
		writeStoreErr(w, err)
		return
	}
	l := core.OrgLimits{Devices: in.Devices, People: in.People, Groups: in.Groups, Policies: in.Policies}
	if err := s.Store.PutOrgLimits(r.Context(), org, l); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "org.limits", org)
	writeJSON(w, 200, toLimitsJSON(l))
}

// DELETE /v1/orgs/{id}/limits は組織の上限を設定の既定に戻す。
func (s *Server) deleteOrgLimits(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	org := r.PathValue("id")
	if err := s.Store.DeleteOrgLimits(r.Context(), org); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "org.limits_reset", org)
	w.WriteHeader(http.StatusNoContent)
}
