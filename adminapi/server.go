package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// FilterEndpoints は端末に設定する通信フィルターの入り口。
type FilterEndpoints struct {
	// DoHBaseURL は "https://dns.example.com"。端末の URL は {DoHBaseURL}/dns-query/{token}。
	DoHBaseURL string
	// DoTDomain は "dns.example.com"。端末のホスト名は {token}.{DoTDomain}。空なら DoT は使わない。
	DoTDomain string
}

// Server は管理の API。
type Server struct {
	Store     core.Store
	Clock     core.Clock
	Engine    *filter.Engine
	Refresher *blocklist.Refresher
	Tokens    []AdminToken
	Endpoints FilterEndpoints
	Logger    *slog.Logger
}

type actorKey struct{}

func actor(ctx context.Context) string { s, _ := ctx.Value(actorKey{}).(string); return s }

// Handler は API の http.Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	api := http.NewServeMux()
	api.HandleFunc("GET /v1/people", s.listPeople)
	api.HandleFunc("POST /v1/people", s.createPerson)
	api.HandleFunc("GET /v1/people/{id}", s.getPerson)
	api.HandleFunc("PATCH /v1/people/{id}", s.updatePerson)
	api.HandleFunc("DELETE /v1/people/{id}", s.deletePerson)

	api.HandleFunc("GET /v1/devices", s.listDevices)
	api.HandleFunc("POST /v1/devices", s.createDevice)
	api.HandleFunc("GET /v1/devices/{id}", s.getDevice)
	api.HandleFunc("PATCH /v1/devices/{id}", s.updateDevice)
	api.HandleFunc("DELETE /v1/devices/{id}", s.deleteDevice)
	api.HandleFunc("POST /v1/devices/{id}/filter-token", s.rotateToken)
	api.HandleFunc("POST /v1/devices/{id}/pause", s.pause)
	api.HandleFunc("DELETE /v1/devices/{id}/pause", s.unpause)
	api.HandleFunc("GET /v1/devices/{id}/queries", s.queries)
	api.HandleFunc("POST /v1/devices/{id}/check", s.check)

	api.HandleFunc("GET /v1/policies", s.listPolicies)
	api.HandleFunc("POST /v1/policies", s.createPolicy)
	api.HandleFunc("GET /v1/policies/{id}", s.getPolicy)
	api.HandleFunc("PUT /v1/policies/{id}", s.putPolicy)
	api.HandleFunc("DELETE /v1/policies/{id}", s.deletePolicy)

	api.HandleFunc("GET /v1/blocklists", s.listBlocklists)
	api.HandleFunc("POST /v1/blocklists", s.createBlocklist)
	api.HandleFunc("DELETE /v1/blocklists/{id}", s.deleteBlocklist)
	api.HandleFunc("POST /v1/blocklists/{id}/refresh", s.refreshBlocklist)

	api.HandleFunc("GET /v1/audit", s.listAudit)

	mux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := authenticate(s.Tokens, r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mdm"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized", "")
			return
		}
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, name)))
	}))
	return mux
}

func (s *Server) audit(r *http.Request, action, target string) {
	if err := s.Store.AppendAudit(r.Context(), core.AuditEvent{At: s.Clock.Now(), Actor: actor(r.Context()), Action: action, Target: target}); err != nil && s.Logger != nil {
		s.Logger.Error("audit", "err", err)
	}
}

// changed は判定に効く変更のあと。記録して判定を読み直させる。
func (s *Server) changed(r *http.Request, action, target string) {
	s.audit(r, action, target)
	s.Engine.Invalidate()
}

func handleInputErr(w http.ResponseWriter, err error) {
	var b badRequest
	if errors.As(err, &b) {
		writeErr(w, http.StatusBadRequest, "invalid_request", b.Error())
		return
	}
	writeStoreErr(w, err)
}

// --- people

func (s *Server) listPeople(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListPeople(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := []personJSON{}
	for _, p := range ps {
		out = append(out, toPersonJSON(p))
	}
	writeJSON(w, 200, map[string]any{"people": out})
}

func (s *Server) createPerson(w http.ResponseWriter, r *http.Request) {
	var in personInput
	if !readJSON(w, r, &in) {
		return
	}
	p := core.Person{ID: core.NewID("per"), Role: core.RoleChild, CreatedAt: s.Clock.Now()}
	if err := in.apply(&p); err != nil {
		handleInputErr(w, err)
		return
	}
	if err := s.Store.CreatePerson(r.Context(), p); err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, "person.create", p.ID)
	writeJSON(w, http.StatusCreated, toPersonJSON(p))
}

func (s *Server) getPerson(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.GetPerson(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, toPersonJSON(p))
}

func (s *Server) updatePerson(w http.ResponseWriter, r *http.Request) {
	var in personInput
	if !readJSON(w, r, &in) {
		return
	}
	p, err := s.Store.GetPerson(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if err := in.apply(&p); err != nil {
		handleInputErr(w, err)
		return
	}
	if err := s.Store.UpdatePerson(r.Context(), p); err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, "person.update", p.ID)
	writeJSON(w, 200, toPersonJSON(p))
}

func (s *Server) deletePerson(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeletePerson(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "person.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- devices

// filterSetup は端末に通信フィルターを設定するための情報。秘密を含むので、作ったときと作り直したときだけ返す。
type filterSetup struct {
	Token           string `json:"token"`
	DoHURL          string `json:"doh_url"`
	DoTHostname     string `json:"dot_hostname,omitempty"`
	AppleProfileURL string `json:"apple_profile_url"`
}

func (s *Server) setup(token string) filterSetup {
	f := filterSetup{
		Token:           token,
		DoHURL:          s.Endpoints.DoHBaseURL + "/dns-query/" + token,
		AppleProfileURL: s.Endpoints.DoHBaseURL + "/setup/apple/" + token + ".mobileconfig",
	}
	if s.Endpoints.DoTDomain != "" {
		f.DoTHostname = token + "." + s.Endpoints.DoTDomain
	}
	return f
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.ListDevices(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	now := s.Clock.Now()
	out := []deviceJSON{}
	for _, d := range ds {
		out = append(out, toDeviceJSON(d, now))
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	var in deviceInput
	if !readJSON(w, r, &in) {
		return
	}
	token, hash := core.NewFilterToken()
	d := core.Device{ID: core.NewID("dev"), FilterTokenHash: hash, CreatedAt: s.Clock.Now()}
	if err := in.apply(&d); err != nil {
		handleInputErr(w, err)
		return
	}
	if err := s.Store.CreateDevice(r.Context(), d); err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, "device.create", d.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"device": toDeviceJSON(d, s.Clock.Now()), "filter": s.setup(token)})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	pol, ok, err := s.Engine.PolicyFor(r.Context(), d)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := map[string]any{"device": toDeviceJSON(d, s.Clock.Now())}
	if ok {
		out["effective_policy_id"] = pol.ID
	}
	writeJSON(w, 200, out)
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	var in deviceInput
	if !readJSON(w, r, &in) {
		return
	}
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if err := in.apply(&d); err != nil {
		handleInputErr(w, err)
		return
	}
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		handleInputErr(w, err)
		return
	}
	s.changed(r, "device.update", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteDevice(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "device.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	token, hash := core.NewFilterToken()
	d.FilterTokenHash = hash
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "device.rotate_filter_token", d.ID)
	writeJSON(w, 200, map[string]any{"filter": s.setup(token)})
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
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	d.PausedUntil = s.Clock.Now().Add(time.Duration(in.Minutes) * time.Minute)
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "device.pause", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) unpause(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	d.PausedUntil = time.Time{}
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "device.unpause", d.ID)
	writeJSON(w, 200, toDeviceJSON(d, s.Clock.Now()))
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.Store.GetDevice(r.Context(), id); err != nil {
		writeStoreErr(w, err)
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
	logs, err := s.Store.ListQueryLogs(r.Context(), id, since, limit)
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
	d, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
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
	out := []policyJSON{}
	for _, p := range ps {
		out = append(out, toPolicyJSON(p))
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
	p, err := in.toPolicy(core.NewID("pol"))
	if err == nil {
		err = s.checkLists(r, p.ListIDs)
	}
	if err != nil {
		handleInputErr(w, err)
		return
	}
	p.UpdatedAt = s.Clock.Now()
	if err := s.Store.CreatePolicy(r.Context(), p); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "policy.create", p.ID)
	writeJSON(w, http.StatusCreated, toPolicyJSON(p))
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.GetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, toPolicyJSON(p))
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var in policyInput
	if !readJSON(w, r, &in) {
		return
	}
	p, err := in.toPolicy(r.PathValue("id"))
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
	s.changed(r, "policy.update", p.ID)
	writeJSON(w, 200, toPolicyJSON(p))
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == filter.DefaultPolicyID {
		writeErr(w, http.StatusConflict, "conflict", "既定のポリシーは消せない")
		return
	}
	if err := s.Store.DeletePolicy(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.changed(r, "policy.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- blocklists

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
	s.audit(r, "blocklist.create", b.ID)
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
	s.changed(r, "blocklist.delete", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) refreshBlocklist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Refresher.Refresh(r.Context(), id); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			writeStoreErr(w, err)
			return
		}
		writeErr(w, http.StatusBadGateway, "fetch_failed", err.Error())
		return
	}
	s.audit(r, "blocklist.refresh", id)
	b, err := s.Store.GetBlocklist(r.Context(), id)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, toBlocklistJSON(b))
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	es, err := s.Store.ListAudit(r.Context(), 200)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	type e struct {
		At     time.Time `json:"at"`
		Actor  string    `json:"actor"`
		Action string    `json:"action"`
		Target string    `json:"target"`
	}
	out := []e{}
	for _, x := range es {
		out = append(out, e{x.At, x.Actor, x.Action, x.Target})
	}
	writeJSON(w, 200, map[string]any{"events": out})
}
