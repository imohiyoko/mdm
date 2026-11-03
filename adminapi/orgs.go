package adminapi

import (
	"net/http"
	"strings"

	"github.com/imohiyoko/mdm/core"
)

// --- orgs

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	os, err := s.Store.ListOrgs(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p := principal(r.Context())
	out := []orgJSON{}
	for _, o := range os {
		if p.CanRead(o.ID) {
			out = append(out, toOrgJSON(o))
		}
	}
	writeJSON(w, 200, map[string]any{"orgs": out})
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	var in orgInput
	if !readJSON(w, r, &in) {
		return
	}
	o := core.Org{ID: core.NewID("org"), Kind: core.OrgFamily, CreatedAt: s.Clock.Now()}
	err := in.apply(&o)
	if err == nil {
		err = s.policyInOrg(r.Context(), o.DefaultPolicyID, o.ID)
	}
	if err == nil {
		err = s.Store.CreateOrg(r.Context(), o)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, o.ID, "org.create", o.ID)
	writeJSON(w, http.StatusCreated, toOrgJSON(o))
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canRead(w, r, id) {
		return
	}
	o, err := s.Store.GetOrg(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, toOrgJSON(o))
}

func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canWrite(w, r, id) {
		return
	}
	var in orgInput
	if !readJSON(w, r, &in) {
		return
	}
	o, err := s.Store.GetOrg(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	err = in.apply(&o)
	if err == nil {
		err = s.policyInOrg(r.Context(), o.DefaultPolicyID, o.ID)
	}
	if err == nil {
		err = s.Store.UpdateOrg(r.Context(), o)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, o.ID, "org.update", o.ID)
	writeJSON(w, 200, toOrgJSON(o))
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteOrg(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "", "org.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- groups

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.Store.ListGroups(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p, org := principal(r.Context()), r.URL.Query().Get("org_id")
	out := []groupJSON{}
	for _, g := range gs {
		if p.CanRead(g.OrgID) && (org == "" || g.OrgID == org) {
			out = append(out, toGroupJSON(g))
		}
	}
	writeJSON(w, 200, map[string]any{"groups": out})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if !readJSON(w, r, &in) {
		return
	}
	org, ok := s.targetOrg(w, r, in.OrgID)
	if !ok {
		return
	}
	unlock, err := s.reserve(r.Context(), org, limitGroups)
	if err != nil {
		writeReserveErr(w, err)
		return
	}
	defer unlock()
	g := core.Group{ID: core.NewID("grp"), OrgID: org, CreatedAt: s.Clock.Now()}
	err = in.apply(&g)
	if err == nil {
		err = s.policyInOrg(r.Context(), g.PolicyID, org)
	}
	if err == nil {
		err = s.Store.CreateGroup(r.Context(), g)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, org, "group.create", g.ID)
	writeJSON(w, http.StatusCreated, toGroupJSON(g))
}

func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request, write bool) (core.Group, bool) {
	g, err := s.Store.GetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return g, false
	}
	if write {
		return g, canWrite(w, r, g.OrgID)
	}
	return g, canRead(w, r, g.OrgID)
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	if g, ok := s.loadGroup(w, r, false); ok {
		writeJSON(w, 200, toGroupJSON(g))
	}
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if !readJSON(w, r, &in) {
		return
	}
	g, ok := s.loadGroup(w, r, true)
	if !ok {
		return
	}
	if in.OrgID != nil && *in.OrgID != g.OrgID {
		writeErr(w, 400, "invalid_request", "org_id は変えられない")
		return
	}
	err := in.apply(&g)
	if err == nil {
		err = s.policyInOrg(r.Context(), g.PolicyID, g.OrgID)
	}
	if err == nil {
		err = s.Store.UpdateGroup(r.Context(), g)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, g.OrgID, "group.update", g.ID)
	writeJSON(w, 200, toGroupJSON(g))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.loadGroup(w, r, true)
	if !ok {
		return
	}
	if err := s.Store.DeleteGroup(r.Context(), g.ID); err != nil {
		writeStoreErr(w, err) // 人が入っていれば 409
		return
	}
	s.changed(r, g.OrgID, "group.delete", g.ID)
	w.WriteHeader(http.StatusNoContent)
}

// --- admins（IAM のユーザーに役割を与える）

func (s *Server) listAdmins(w http.ResponseWriter, r *http.Request) {
	bs, err := s.Store.ListAdminBindings(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p := principal(r.Context())
	out := []bindingJSON{}
	for _, b := range bs {
		if p.IsServerAdmin() || b.OrgID != "" && p.CanWrite(b.OrgID) {
			out = append(out, toBindingJSON(b))
		}
	}
	writeJSON(w, 200, map[string]any{"admins": out})
}

func (s *Server) createAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Issuer  string         `json:"issuer"`
		Subject string         `json:"subject"`
		Label   string         `json:"label"`
		Role    core.AdminRole `json:"role"`
		OrgID   string         `json:"org_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Issuer == "" {
		in.Issuer = s.Issuer
	}
	in.Subject = strings.TrimSpace(in.Subject)
	switch {
	case in.Issuer == "":
		writeErr(w, 400, "invalid_request", "issuer が要る（設定に oidc が無い）")
		return
	case in.Subject == "" || len(in.Subject) > 255 || len(in.Label) > 255:
		writeErr(w, 400, "invalid_request", "subject は 1〜255 文字（IAM の sub）")
		return
	case !in.Role.Valid():
		writeErr(w, 400, "invalid_request", "role は server_admin・org_admin・org_viewer のどれか")
		return
	case in.Role == core.AdminServer && in.OrgID != "":
		writeErr(w, 400, "invalid_request", "server_admin に org_id は付けない")
		return
	case in.Role != core.AdminServer && in.OrgID == "":
		writeErr(w, 400, "invalid_request", "org_admin・org_viewer には org_id が要る")
		return
	}
	// 組織の管理者は、自分の組織の管理者だけを足せる。サーバー全体の管理者を足せるのはサーバー全体の管理者だけ。
	if in.Role == core.AdminServer {
		if !serverAdmin(w, r) {
			return
		}
	} else if _, ok := s.targetOrg(w, r, &in.OrgID); !ok {
		return
	}
	b := core.AdminBinding{ID: core.NewID("adm"), Issuer: in.Issuer, Subject: in.Subject, Label: in.Label, Role: in.Role, OrgID: in.OrgID, CreatedAt: s.Clock.Now()}
	if err := s.Store.CreateAdminBinding(r.Context(), b); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, b.OrgID, "admin.create", b.ID)
	writeJSON(w, http.StatusCreated, toBindingJSON(b))
}

func (s *Server) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	bs, err := s.Store.ListAdminBindings(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	for _, b := range bs {
		if b.ID != id {
			continue
		}
		if b.OrgID == "" && !serverAdmin(w, r) || b.OrgID != "" && !canWrite(w, r, b.OrgID) {
			return
		}
		if err := s.Store.DeleteAdminBinding(r.Context(), id); err != nil {
			writeStoreErr(w, err)
			return
		}
		s.audit(r, b.OrgID, "admin.delete", id)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeErr(w, http.StatusNotFound, "not_found", "")
}
