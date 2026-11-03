package adminapi

import (
	"context"
	"errors"
	"github.com/imohiyoko/mdm/apple"
	"github.com/imohiyoko/mdm/compliance"
	"github.com/imohiyoko/mdm/network"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/windows"
)

// FilterEndpoints は端末に設定する通信フィルターの入り口。
type FilterEndpoints struct {
	// DoHBaseURL は "https://dns.example.com"。端末の URL は {DoHBaseURL}/dns-query/{token}。
	DoHBaseURL string
	// DoTDomain は "dns.example.com"。端末のホスト名は {label}.{DoTDomain}。空なら DoT は使わない。
	DoTDomain string
}

// Server は管理の API。
type Server struct {
	Store     core.Store
	Clock     core.Clock
	Engine    *filter.Engine
	Refresher *blocklist.Refresher
	Tokens    []AdminToken
	// Introspector があれば、IAM のアクセストークンでも使える。Issuer はその IAM の issuer。
	Introspector Introspector
	Issuer       string
	Endpoints    FilterEndpoints
	// Android があれば Android の端末を管理できる（無ければその API は 501）。
	Android *android.Service
	// Windows があれば Windows の端末を管理できる。
	Windows *windows.Service
	// Apple があれば iPhone・iPad・Mac の端末を管理できる。
	Apple *apple.Service
	// Network があれば Wi-Fi などに入るための端末の証明書を発行できる。
	Network *network.Service
	// StaticRADIUSPrefixes は設定に書いたルーターのアドレス。組織の管理者はこれと重なるルーターを登録できない。
	StaticRADIUSPrefixes []netip.Prefix
	// RADIUSChanged は組織のルーターの登録が変わったときに呼ぶ（RADIUS のサーバーが読み直す）。
	RADIUSChanged func()
	// Signup は IAM でログインした人が自分で組織を作れるようにする設定。
	Signup Signup
	// Compliance があれば端末の準拠を判定し、IAM に知らせる。
	Compliance *compliance.Service
	Logger     *slog.Logger
}

// Handler は API の http.Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	api := http.NewServeMux()
	api.HandleFunc("GET /v1/me", s.me)

	api.HandleFunc("GET /v1/orgs", s.listOrgs)
	api.HandleFunc("POST /v1/orgs", s.createOrg)
	api.HandleFunc("GET /v1/orgs/{id}", s.getOrg)
	api.HandleFunc("PATCH /v1/orgs/{id}", s.updateOrg)
	api.HandleFunc("DELETE /v1/orgs/{id}", s.deleteOrg)
	api.HandleFunc("POST /v1/signup", s.signup)
	api.HandleFunc("POST /v1/invitations/accept", s.acceptInvitation)
	api.HandleFunc("GET /v1/orgs/{id}/invitations", s.listInvitations)
	api.HandleFunc("POST /v1/orgs/{id}/invitations", s.createInvitation)
	api.HandleFunc("DELETE /v1/orgs/{id}/invitations/{iid}", s.deleteInvitation)
	api.HandleFunc("GET /v1/orgs/{id}/apple/push", s.getApplePush)
	api.HandleFunc("PUT /v1/orgs/{id}/apple/push", s.putApplePush)
	api.HandleFunc("DELETE /v1/orgs/{id}/apple/push", s.deleteApplePush)
	api.HandleFunc("POST /v1/orgs/{id}/apple/push/csr", s.createApplePushCSR)
	api.HandleFunc("GET /v1/orgs/{id}/android", s.getOrgAndroid)
	api.HandleFunc("POST /v1/orgs/{id}/android/signup", s.androidSignup)
	api.HandleFunc("GET /v1/orgs/{id}/radius-clients", s.listRADIUSClients)
	api.HandleFunc("POST /v1/orgs/{id}/radius-clients", s.createRADIUSClient)
	api.HandleFunc("DELETE /v1/orgs/{id}/radius-clients/{cid}", s.deleteRADIUSClient)
	api.HandleFunc("GET /v1/orgs/{id}/ssf-receivers", s.listSSFReceivers)
	api.HandleFunc("POST /v1/orgs/{id}/ssf-receivers", s.createSSFReceiver)
	api.HandleFunc("DELETE /v1/orgs/{id}/ssf-receivers/{rid}", s.deleteSSFReceiver)

	api.HandleFunc("GET /v1/groups", s.listGroups)
	api.HandleFunc("POST /v1/groups", s.createGroup)
	api.HandleFunc("GET /v1/groups/{id}", s.getGroup)
	api.HandleFunc("PATCH /v1/groups/{id}", s.updateGroup)
	api.HandleFunc("DELETE /v1/groups/{id}", s.deleteGroup)

	api.HandleFunc("GET /v1/admins", s.listAdmins)
	api.HandleFunc("POST /v1/admins", s.createAdmin)
	api.HandleFunc("DELETE /v1/admins/{id}", s.deleteAdmin)

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
	api.HandleFunc("POST /v1/devices/{id}/network-cert", s.issueNetworkCert)
	api.HandleFunc("GET /v1/devices/{id}/network-cert", s.listNetworkCerts)
	api.HandleFunc("DELETE /v1/devices/{id}/network-cert", s.revokeNetworkCerts)
	api.HandleFunc("POST /v1/devices/{id}/pause", s.pause)
	api.HandleFunc("DELETE /v1/devices/{id}/pause", s.unpause)
	api.HandleFunc("GET /v1/devices/{id}/queries", s.queries)
	api.HandleFunc("POST /v1/devices/{id}/check", s.check)
	api.HandleFunc("POST /v1/devices/{id}/enroll", s.enrollDevice)
	api.HandleFunc("POST /v1/devices/{id}/commands", s.deviceCommand)
	api.HandleFunc("GET /v1/devices/{id}/commands", s.listCommands)
	api.HandleFunc("POST /v1/devices/{id}/unenroll", s.unenrollDevice)

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
		p, ok := s.authenticate(r)
		if ok && len(p.Roles) == 0 && !roleless[r.Method+" "+r.URL.Path] {
			ok = false // IAM でログインできても、管理者として登録されていなければ、サインアップと招待を受けることしかできない
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mdm"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized", "")
			return
		}
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}))
	return mux
}

// roleless は役割の無い人（IAM でログインしただけの人）も使える API。
var roleless = map[string]bool{
	"GET /v1/me":                  true,
	"POST /v1/signup":             true,
	"POST /v1/invitations/accept": true,
}

func (s *Server) audit(r *http.Request, orgID, action, target string) {
	e := core.AuditEvent{At: s.Clock.Now(), OrgID: orgID, Actor: principal(r.Context()).Name, Action: action, Target: target}
	if err := s.Store.AppendAudit(r.Context(), e); err != nil && s.Logger != nil {
		s.Logger.Error("audit", "err", err)
	}
}

// changed は判定に効く変更のあと。記録して判定を読み直す。
func (s *Server) changed(r *http.Request, orgID, action, target string) {
	s.audit(r, orgID, action, target)
	if err := s.Engine.Refresh(r.Context()); err != nil && s.Logger != nil {
		// 前の内容のまま判定を続け、後ろで読み直す。
		s.Logger.Error("filter refresh", "err", err)
	}
	if s.Android != nil {
		s.Android.Kick() // 管理している端末にポリシーを配り直す
	}
	if s.Apple != nil {
		s.Apple.Kick()
	}
	if s.Compliance != nil {
		s.Compliance.Kick()
	}
}

func handleInputErr(w http.ResponseWriter, err error) {
	var b badRequest
	if errors.As(err, &b) {
		writeErr(w, http.StatusBadRequest, "invalid_request", b.Error())
		return
	}
	writeStoreErr(w, err)
}

// canRead は組織 orgID のものを見られるか。見られなければ、あることも教えない（404）。
func canRead(w http.ResponseWriter, r *http.Request, orgID string) bool {
	if !principal(r.Context()).CanRead(orgID) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return false
	}
	return true
}

// canWrite は組織 orgID のものを変えられるか。
func canWrite(w http.ResponseWriter, r *http.Request, orgID string) bool {
	p := principal(r.Context())
	if !p.CanRead(orgID) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return false
	}
	if !p.CanWrite(orgID) {
		writeErr(w, http.StatusForbidden, "forbidden", "この操作の権限が無い")
		return false
	}
	return true
}

func serverAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !principal(r.Context()).IsServerAdmin() {
		writeErr(w, http.StatusForbidden, "forbidden", "サーバー全体の管理者だけができる")
		return false
	}
	return true
}

// targetOrg は作るものの組織。省いたら、組織を 1 つだけ管理する管理者のその組織。
func (s *Server) targetOrg(w http.ResponseWriter, r *http.Request, given *string) (string, bool) {
	org := ""
	if given != nil {
		org = *given
	}
	if org == "" {
		org = principal(r.Context()).soleOrg()
	}
	if org == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "org_id が要る")
		return "", false
	}
	if !canWrite(w, r, org) {
		return "", false
	}
	if _, err := s.Store.GetOrg(r.Context(), org); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			writeErr(w, http.StatusBadRequest, "invalid_request", "org_id の組織が無い")
		} else {
			writeStoreErr(w, err)
		}
		return "", false
	}
	return org, true
}

// policyInOrg はポリシー id が組織 orgID から使えるか（同じ組織か、サーバー全体のもの）。
func (s *Server) policyInOrg(ctx context.Context, id, orgID string) error {
	if id == "" {
		return nil
	}
	p, err := s.Store.GetPolicy(ctx, id)
	if errors.Is(err, core.ErrNotFound) || err == nil && p.OrgID != "" && p.OrgID != orgID {
		return bad("policy_id のポリシーがこの組織に無い")
	}
	return err
}

func (s *Server) groupsInOrg(ctx context.Context, ids []string, orgID string) error {
	for _, id := range ids {
		g, err := s.Store.GetGroup(ctx, id)
		if errors.Is(err, core.ErrNotFound) || err == nil && g.OrgID != orgID {
			return bad("group_ids のグループ %q がこの組織に無い", id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) personInOrg(ctx context.Context, id, orgID string) error {
	if id == "" {
		return nil
	}
	p, err := s.Store.GetPerson(ctx, id)
	if errors.Is(err, core.ErrNotFound) || err == nil && p.OrgID != orgID {
		return bad("person_id の人がこの組織に無い")
	}
	return err
}

// --- me

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r.Context())
	roles := []map[string]string{}
	for _, b := range p.Roles {
		m := map[string]string{"role": string(b.Role)}
		if b.OrgID != "" {
			m["org_id"] = b.OrgID
		}
		roles = append(roles, m)
	}
	writeJSON(w, 200, map[string]any{"name": p.Name, "roles": roles, "can_signup": s.Signup.Enabled && p.Subject != ""})
}

// --- audit

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	es, err := s.Store.ListAudit(r.Context(), 500)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	p := principal(r.Context())
	type e struct {
		At     time.Time `json:"at"`
		OrgID  string    `json:"org_id,omitempty"`
		Actor  string    `json:"actor"`
		Action string    `json:"action"`
		Target string    `json:"target"`
	}
	out := []e{}
	for _, x := range es {
		// サーバー全体の操作は、サーバー全体の管理者だけが見る。
		if !p.IsServerAdmin() && (x.OrgID == "" || !p.CanRead(x.OrgID)) {
			continue
		}
		out = append(out, e{x.At, x.OrgID, x.Actor, x.Action, x.Target})
		if len(out) == 200 {
			break
		}
	}
	writeJSON(w, 200, map[string]any{"events": out})
}
