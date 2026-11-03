package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

func orgFilter(r *http.Request) func(orgID string) bool {
	p, org := principal(r.Context()), r.URL.Query().Get("org_id")
	return func(orgID string) bool { return p.CanRead(orgID) && (org == "" || orgID == org) }
}

// --- people

func (s *Server) listPeople(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListPeople(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	visible := orgFilter(r)
	out := []personJSON{}
	for _, p := range ps {
		if visible(p.OrgID) {
			out = append(out, toPersonJSON(p))
		}
	}
	writeJSON(w, 200, map[string]any{"people": out})
}

func (s *Server) checkPerson(ctx context.Context, p core.Person) error {
	if err := s.policyInOrg(ctx, p.PolicyID, p.OrgID); err != nil {
		return err
	}
	return s.groupsInOrg(ctx, p.GroupIDs, p.OrgID)
}

func (s *Server) createPerson(w http.ResponseWriter, r *http.Request) {
	var in personInput
	if !readJSON(w, r, &in) {
		return
	}
	org, ok := s.targetOrg(w, r, in.OrgID)
	if !ok {
		return
	}
	unlock, err := s.reserve(r.Context(), org, limitPeople)
	if err != nil {
		writeReserveErr(w, err)
		return
	}
	defer unlock()
	p := core.Person{ID: core.NewID("per"), OrgID: org, Role: core.RoleChild, CreatedAt: s.Clock.Now()}
	err = in.apply(&p)
	if err == nil {
		err = s.checkPerson(r.Context(), p)
	}
	if err == nil {
		err = s.Store.CreatePerson(r.Context(), p)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, org, "person.create", p.ID)
	writeJSON(w, http.StatusCreated, toPersonJSON(p))
}

func (s *Server) loadPerson(w http.ResponseWriter, r *http.Request, write bool) (core.Person, bool) {
	p, err := s.Store.GetPerson(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return p, false
	}
	if write {
		return p, canWrite(w, r, p.OrgID)
	}
	return p, canRead(w, r, p.OrgID)
}

func (s *Server) getPerson(w http.ResponseWriter, r *http.Request) {
	if p, ok := s.loadPerson(w, r, false); ok {
		writeJSON(w, 200, toPersonJSON(p))
	}
}

func (s *Server) updatePerson(w http.ResponseWriter, r *http.Request) {
	var in personInput
	if !readJSON(w, r, &in) {
		return
	}
	p, ok := s.loadPerson(w, r, true)
	if !ok {
		return
	}
	if in.OrgID != nil && *in.OrgID != p.OrgID {
		writeErr(w, 400, "invalid_request", "org_id は変えられない")
		return
	}
	oldEmail := p.Email
	err := in.apply(&p)
	if err == nil {
		err = s.checkPerson(r.Context(), p)
	}
	if err == nil {
		err = s.Store.UpdatePerson(r.Context(), p)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	if p.Email != oldEmail {
		s.resendCompliance(r, func(d core.Device) bool { return d.PersonID == p.ID })
	}
	s.changed(r, p.OrgID, "person.update", p.ID)
	writeJSON(w, 200, toPersonJSON(p))
}

func (s *Server) deletePerson(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadPerson(w, r, true)
	if !ok {
		return
	}
	if err := s.Store.DeletePerson(r.Context(), p.ID); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, p.OrgID, "person.delete", p.ID)
	w.WriteHeader(http.StatusNoContent)
}

// --- devices

// filterSetup は端末に通信フィルターを設定するための情報。秘密を含むので、作ったときと作り直したときだけ返す。
// DoT のホスト名は暗号化されずに流れるので、DoH の秘密とは別の値にしている。
type filterSetup struct {
	Token           string `json:"token"`
	DoHURL          string `json:"doh_url"`
	DoTHostname     string `json:"dot_hostname,omitempty"`
	AppleProfileURL string `json:"apple_profile_url"`
}

// newFilterSecrets は DoH の秘密と DoT のラベルを作って端末に入れ、設定の情報と DoT のラベル（平文）を返す。
func (s *Server) newFilterSecrets(d *core.Device) (filterSetup, string) {
	token, hash := core.NewFilterToken()
	label, labelHash := core.NewFilterToken()
	d.FilterTokenHash, d.DoTLabelHash = hash, labelHash
	f := filterSetup{
		Token:           token,
		DoHURL:          s.Endpoints.DoHBaseURL + "/dns-query/" + token,
		AppleProfileURL: s.Endpoints.DoHBaseURL + "/setup/apple/" + token + ".mobileconfig",
	}
	if s.Endpoints.DoTDomain != "" {
		f.DoTHostname = label + "." + s.Endpoints.DoTDomain
	}
	return f, label
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.ListDevices(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	visible, now := orgFilter(r), s.Clock.Now()
	out := []deviceJSON{}
	for _, d := range ds {
		if visible(d.OrgID) {
			out = append(out, toDeviceJSON(d, now))
		}
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (s *Server) checkDevice(ctx context.Context, d core.Device) error {
	if err := s.policyInOrg(ctx, d.PolicyID, d.OrgID); err != nil {
		return err
	}
	return s.personInOrg(ctx, d.PersonID, d.OrgID)
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	var in deviceInput
	if !readJSON(w, r, &in) {
		return
	}
	org, ok := s.targetOrg(w, r, in.OrgID)
	if !ok {
		return
	}
	unlock, err := s.reserve(r.Context(), org, limitDevices)
	if err != nil {
		writeReserveErr(w, err)
		return
	}
	defer unlock()
	d := core.Device{ID: core.NewID("dev"), OrgID: org, CreatedAt: s.Clock.Now()}
	setup, _ := s.newFilterSecrets(&d)
	err = in.apply(&d)
	if err == nil {
		err = s.checkDevice(r.Context(), d)
	}
	if err == nil {
		err = s.Store.CreateDevice(r.Context(), d)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, org, "device.create", d.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"device": toDeviceJSON(d, s.Clock.Now()), "filter": setup})
}

func (s *Server) loadDevice(w http.ResponseWriter, r *http.Request, write bool) (core.Device, bool) {
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return d, false
	}
	if write {
		return d, canWrite(w, r, d.OrgID)
	}
	return d, canRead(w, r, d.OrgID)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, false)
	if !ok {
		return
	}
	pol, found, err := s.Engine.PolicyFor(r.Context(), d)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := map[string]any{"device": toDeviceJSON(d, s.Clock.Now())}
	if found {
		out["effective_policy_id"] = pol.ID
	}
	if c, err := s.Store.GetCompliance(r.Context(), d.ID); err == nil {
		out["compliance"] = map[string]any{"compliant": c.Compliant, "reasons": nonNil(c.Reasons), "changed_at": c.ChangedAt, "evaluated_at": c.EvaluatedAt}
	} else if !errors.Is(err, core.ErrNotFound) {
		writeStoreErr(w, err)
		return
	}
	if m, err := s.Store.GetManaged(r.Context(), d.ID); err == nil {
		out["managed"] = toManagedJSON(m)
	} else if !errors.Is(err, core.ErrNotFound) {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	var in deviceInput
	if !readJSON(w, r, &in) {
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	if in.OrgID != nil && *in.OrgID != d.OrgID {
		writeErr(w, 400, "invalid_request", "org_id は変えられない")
		return
	}
	if in.Platform != nil && *in.Platform != d.Platform {
		if managed, err := s.isManaged(r, d.ID); err != nil || managed {
			if err != nil {
				writeStoreErr(w, err)
			} else {
				writeErr(w, http.StatusConflict, "managed", "管理している端末の platform は変えられない（先に管理を外す）")
			}
			return
		}
	}
	oldPerson := d.PersonID
	err := in.apply(&d)
	if err == nil {
		err = s.checkDevice(r.Context(), d)
	}
	if err == nil {
		err = s.Store.UpdateDevice(r.Context(), d)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	if d.PersonID != oldPerson {
		s.resendCompliance(r, func(x core.Device) bool { return x.ID == d.ID })
	}
	s.changed(r, d.OrgID, "device.update", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	if managed, err := s.isManaged(r, d.ID); err != nil || managed {
		if err != nil {
			writeStoreErr(w, err)
		} else {
			writeErr(w, http.StatusConflict, "managed", "管理している端末は消せない（先に unenroll で管理を外す）")
		}
		return
	}
	if err := s.Store.DeleteDevice(r.Context(), d.ID); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, d.OrgID, "device.delete", d.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	prev := d
	setup, label := s.newFilterSecrets(&d)
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	if s.Android != nil {
		// 管理している Android の端末には新しいホスト名を配る。配れなければ元に戻す（端末の通信が止まるため）。
		if err := s.Android.SetFilterHost(r.Context(), d, label); err != nil {
			if err2 := s.Store.UpdateDevice(r.Context(), prev); err2 != nil && s.Logger != nil {
				s.Logger.Error("restore filter secrets", "err", err2)
			}
			writeAndroidErr(w, err)
			return
		}
	}
	if s.Apple != nil {
		// 管理している iPhone・Mac には新しい DoH の URL のプロファイルを送る。
		if err := s.Apple.SetFilterToken(r.Context(), d, setup.Token); err != nil {
			if err2 := s.Store.UpdateDevice(r.Context(), prev); err2 != nil && s.Logger != nil {
				s.Logger.Error("restore filter secrets", "err", err2)
			}
			writeStoreErr(w, err)
			return
		}
	}
	s.changed(r, d.OrgID, "device.rotate_filter_token", d.ID)
	writeJSON(w, 200, map[string]any{"filter": setup})
}

func (s *Server) pause(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes int `json:"minutes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Minutes < 1 || in.Minutes > 7*24*60 {
		writeErr(w, 400, "invalid_request", "minutes は 1〜10080")
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	d.PausedUntil = s.Clock.Now().Add(time.Duration(in.Minutes) * time.Minute)
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, d.OrgID, "device.pause", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) unpause(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	d.PausedUntil = time.Time{}
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, d.OrgID, "device.unpause", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, false)
	if !ok {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeErr(w, 400, "invalid_request", "limit は 1〜1000")
			return
		}
		limit = n
	}
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, 400, "invalid_request", "since は RFC 3339")
			return
		}
		since = t
	}
	logs, err := s.Store.ListQueryLogs(r.Context(), d.ID, since, limit)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	type q struct {
		At     time.Time   `json:"at"`
		Name   string      `json:"name"`
		Type   string      `json:"type"`
		Action core.Action `json:"action"`
		Reason string      `json:"reason"`
	}
	out := []q{}
	for _, l := range logs {
		out = append(out, q{l.At, l.Name, l.Type, l.Action, l.Reason})
	}
	writeJSON(w, 200, map[string]any{"queries": out})
}

// check は「この端末でこのサイトは止まるか」を確かめる。記録は残さない。
func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if filter.Normalize(in.Name) == "" {
		writeErr(w, 400, "invalid_request", "name はドメイン")
		return
	}
	d, ok := s.loadDevice(w, r, false)
	if !ok {
		return
	}
	dec, pol, err := s.Engine.Decide(r.Context(), d, in.Name)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"action": dec.Action, "reason": dec.Reason, "matched": dec.Matched, "policy_id": pol.ID})
}

// --- policies

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p, org := principal(r.Context()), r.URL.Query().Get("org_id")
	out := []policyJSON{}
	for _, x := range ps {
		// org_id を指定したら、その組織から使えるもの（その組織のものとサーバー全体のもの）。
		if p.CanRead(x.OrgID) && (org == "" || x.OrgID == org || x.OrgID == "") {
			out = append(out, toPolicyJSON(x))
		}
	}
	writeJSON(w, 200, map[string]any{"policies": out})
}

func (s *Server) checkLists(r *http.Request, ids []string) error {
	for _, id := range ids {
		if _, err := s.Store.GetBlocklist(r.Context(), id); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return bad("blocklists に無い一覧 %q", id)
			}
			return err
		}
	}
	return nil
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var in policyInput
	if !readJSON(w, r, &in) {
		return
	}
	if in.OrgID == "" {
		in.OrgID = principal(r.Context()).soleOrg()
	}
	if in.OrgID == "" {
		if !serverAdmin(w, r) {
			return
		}
	} else if _, ok := s.targetOrg(w, r, &in.OrgID); !ok {
		return
	}
	p, err := in.toPolicy(core.NewID("pol"))
	if err == nil {
		err = s.checkLists(r, p.ListIDs)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	p.UpdatedAt = s.Clock.Now()
	if p.OrgID != "" {
		unlock, err := s.reserve(r.Context(), p.OrgID, limitPolicies)
		if err != nil {
			writeReserveErr(w, err)
			return
		}
		defer unlock()
	}
	if err := s.Store.CreatePolicy(r.Context(), p); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, p.OrgID, "policy.create", p.ID)
	writeJSON(w, http.StatusCreated, toPolicyJSON(p))
}

func (s *Server) loadPolicy(w http.ResponseWriter, r *http.Request, write bool) (core.Policy, bool) {
	p, err := s.Store.GetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return p, false
	}
	if write {
		return p, canWrite(w, r, p.OrgID)
	}
	return p, canRead(w, r, p.OrgID)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	if p, ok := s.loadPolicy(w, r, false); ok {
		writeJSON(w, 200, toPolicyJSON(p))
	}
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var in policyInput
	if !readJSON(w, r, &in) {
		return
	}
	cur, ok := s.loadPolicy(w, r, true)
	if !ok {
		return
	}
	if in.OrgID != "" && in.OrgID != cur.OrgID {
		writeErr(w, 400, "invalid_request", "org_id は変えられない")
		return
	}
	in.OrgID = cur.OrgID
	p, err := in.toPolicy(cur.ID)
	if err == nil {
		err = s.checkLists(r, p.ListIDs)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	p.UpdatedAt = s.Clock.Now()
	if err := s.Store.UpdatePolicy(r.Context(), p); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, p.OrgID, "policy.update", p.ID)
	writeJSON(w, 200, toPolicyJSON(p))
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == filter.DefaultPolicyID {
		writeErr(w, http.StatusConflict, "conflict", "既定のポリシーは消せない")
		return
	}
	p, ok := s.loadPolicy(w, r, true)
	if !ok {
		return
	}
	// 組織の既定に使われているポリシーは消さない（組織の表は外部キーで守っていないため）。
	orgs, err := s.Store.ListOrgs(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	for _, o := range orgs {
		if o.DefaultPolicyID == p.ID {
			writeErr(w, http.StatusConflict, "conflict", "組織 "+o.ID+" の既定のポリシー")
			return
		}
	}
	if err := s.Store.DeletePolicy(r.Context(), p.ID); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, p.OrgID, "policy.delete", p.ID)
	w.WriteHeader(http.StatusNoContent)
}

// --- blocklists（サーバー全体で共有する。変えられるのはサーバー全体の管理者だけ）

func (s *Server) listBlocklists(w http.ResponseWriter, r *http.Request) {
	bs, err := s.Store.ListBlocklists(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := []blocklistJSON{}
	for _, b := range bs {
		out = append(out, toBlocklistJSON(b))
	}
	writeJSON(w, 200, map[string]any{"blocklists": out})
}

func (s *Server) createBlocklist(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	var in struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" || len(in.Name) > 100 {
		writeErr(w, 400, "invalid_request", "name は 1〜100 文字")
		return
	}
	if err := blocklist.ValidateURL(in.URL); err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	b := core.Blocklist{ID: core.NewID("bl"), Name: in.Name, URL: in.URL}
	if err := s.Store.CreateBlocklist(r.Context(), b); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, "", "blocklist.create", b.ID)
	// 取り込みは時間がかかるので、後ろで行う。
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := s.Refresher.Refresh(ctx, b.ID); err != nil && s.Logger != nil {
			s.Logger.Warn("refresh blocklist", "id", b.ID, "err", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, toBlocklistJSON(b))
}

func (s *Server) deleteBlocklist(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	ps, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	for _, p := range ps {
		if indexOf(p.ListIDs, id) >= 0 {
			writeErr(w, http.StatusConflict, "conflict", "ポリシー "+p.ID+" が使っている")
			return
		}
	}
	if err := s.Store.DeleteBlocklist(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "", "blocklist.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) refreshBlocklist(w http.ResponseWriter, r *http.Request) {
	if !serverAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.Refresher.Refresh(r.Context(), id); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			writeStoreErr(w, err)
			return
		}
		writeErr(w, http.StatusBadGateway, "fetch_failed", err.Error())
		return
	}
	s.audit(r, "", "blocklist.refresh", id)
	b, err := s.Store.GetBlocklist(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, toBlocklistJSON(b))
}

// resendCompliance は、持ち主やメールアドレスが変わった端末の準拠の状態を IAM にもう一度知らせる。失敗しても操作は止めない。
func (s *Server) resendCompliance(r *http.Request, match func(core.Device) bool) {
	if s.Compliance == nil {
		return
	}
	ds, err := s.Store.ListDevices(r.Context())
	if err == nil {
		var ids []string
		for _, d := range ds {
			if match(d) {
				ids = append(ids, d.ID)
			}
		}
		err = s.Compliance.Resend(r.Context(), ids...)
	}
	if err != nil && s.Logger != nil {
		s.Logger.Error("resend compliance", "err", err)
	}
}
