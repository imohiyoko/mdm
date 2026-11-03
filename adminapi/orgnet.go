package adminapi

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/ssf"
)

// 組織の管理者が自分で登録する、組織のルーター（Wi-Fi の RADIUS のクライアント）と準拠の知らせの受け手（その組織の IAM）。
// どちらもほかの組織に影響しないように絞る：ルーターのアドレスはインターネットのもので、ほかと重ならないこと。
// 知らせの受け手はインターネットの https の URL だけ（送るときも内側のアドレスにはつながない）。

const (
	maxRADIUSClientsPerOrg = 20
	maxSSFReceiversPerOrg  = 5
)

var radiusMu sync.Mutex // 重なりの確かめと登録のあいだに、ほかの登録を割り込ませない

// parseRouterAddress は 203.0.113.10 か 203.0.113.0/28 のようなアドレスを読む。
func parseRouterAddress(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, bad("address は IP か CIDR")
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, bad("address は IP か CIDR")
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	if p.Addr().Is4() && p.Bits() < 24 || p.Addr().Is6() && p.Bits() < 48 {
		return p, bad("address の範囲が広すぎる（IPv4 は /24、IPv6 は /48 まで）")
	}
	if !ssf.PublicAddr(p.Addr()) {
		return p, bad("address はインターネットのアドレスにする（家の中のアドレスはサーバーの設定の radius.clients に書く）")
	}
	return p, nil
}

func radiusClientJSON(c core.RADIUSClient) map[string]any {
	return map[string]any{"id": c.ID, "org_id": c.OrgID, "name": c.Name, "address": c.Prefix.String(), "created_at": c.CreatedAt}
}

func (s *Server) listRADIUSClients(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canRead(w, r, org) || !s.networkReady(w) {
		return
	}
	cs, err := s.Store.ListRADIUSClients(r.Context(), org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := []map[string]any{}
	for _, c := range cs {
		out = append(out, radiusClientJSON(c))
	}
	writeJSON(w, 200, map[string]any{"radius_clients": out, "server_name": s.Network.ServerName})
}

// POST /v1/orgs/{id}/radius-clients はルーターを登録する。共有の秘密はこのときだけ返す。
func (s *Server) createRADIUSClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.networkReady(w) {
		return
	}
	if in.Name == "" || len(in.Name) > 100 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "name は 1〜100 文字")
		return
	}
	p, err := parseRouterAddress(in.Address)
	if err != nil {
		handleInputErr(w, err)
		return
	}
	ctx := r.Context()
	radiusMu.Lock()
	defer radiusMu.Unlock()
	all, err := s.Store.ListRADIUSClients(ctx, "")
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	n := 0
	for _, c := range all {
		if c.Prefix.Overlaps(p) {
			writeErr(w, http.StatusConflict, "address_in_use", "そのアドレスはほかのルーターの登録と重なっている")
			return
		}
		if c.OrgID == org {
			n++
		}
	}
	for _, sp := range s.StaticRADIUSPrefixes {
		if sp.Overlaps(p) {
			writeErr(w, http.StatusConflict, "address_in_use", "そのアドレスはほかのルーターの登録と重なっている")
			return
		}
	}
	if n >= maxRADIUSClientsPerOrg {
		writeErr(w, http.StatusConflict, "too_many", "ルーターは 1 つの組織に 20 台まで")
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	c := core.RADIUSClient{ID: core.NewID("rdc"), OrgID: org, Name: in.Name, Prefix: p,
		Secret: base64.RawURLEncoding.EncodeToString(b), CreatedAt: s.Clock.Now()}
	if err := s.Store.CreateRADIUSClient(ctx, c); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "radius_client.create", c.ID)
	s.radiusChanged()
	out := radiusClientJSON(c)
	out["secret"] = c.Secret
	out["server_name"] = s.Network.ServerName
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, out)
}

func (s *Server) deleteRADIUSClient(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.networkReady(w) {
		return
	}
	if err := s.Store.DeleteRADIUSClient(r.Context(), org, r.PathValue("cid")); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "radius_client.delete", r.PathValue("cid"))
	s.radiusChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) radiusChanged() {
	if s.RADIUSChanged != nil {
		s.RADIUSChanged()
	}
}

// --- 準拠の知らせの受け手

func (s *Server) ssfReady(w http.ResponseWriter) bool {
	if s.Compliance == nil || !s.Compliance.Transmitter.Enabled() || s.Compliance.Transmitter.Dynamic == nil {
		writeErr(w, http.StatusNotImplemented, "ssf_not_configured", "準拠の知らせ（SSF）が使えない")
		return false
	}
	return true
}

func ssfReceiverJSON(x core.SSFReceiver) map[string]any {
	return map[string]any{"id": x.ID, "org_id": x.OrgID, "name": x.Name, "url": x.URL, "audience": x.Audience, "created_at": x.CreatedAt}
}

func (s *Server) listSSFReceivers(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canRead(w, r, org) || !s.ssfReady(w) {
		return
	}
	rs, err := s.Store.ListSSFReceivers(r.Context(), org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := []map[string]any{}
	for _, x := range rs {
		out = append(out, ssfReceiverJSON(x))
	}
	iss := s.Compliance.Transmitter.Issuer
	// IAM の側には、この issuer と jwks_uri で MDM を送信側として登録する。
	writeJSON(w, 200, map[string]any{"ssf_receivers": out, "issuer": iss, "jwks_uri": iss + "/.well-known/jwks.json"})
}

func validReceiverURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(s) > 2000 {
		return false
	}
	// IP で書くなら、インターネットのアドレスだけ（名前は送るときにつなぐ先で確かめる）。
	if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && !ssf.PublicAddr(a) {
		return false
	}
	return u.Hostname() != "localhost"
}

// POST /v1/orgs/{id}/ssf-receivers は準拠の知らせの受け手（その組織の IAM）を登録する。push_token は返さない。
func (s *Server) createSSFReceiver(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		PushToken string `json:"push_token"`
		Audience  string `json:"audience"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.ssfReady(w) {
		return
	}
	switch {
	case in.Name == "" || len(in.Name) > 100:
		writeErr(w, http.StatusBadRequest, "invalid_request", "name は 1〜100 文字")
		return
	case !validReceiverURL(in.URL):
		writeErr(w, http.StatusBadRequest, "invalid_request", "url はインターネットの https の URL")
		return
	case len(in.PushToken) < 16 || len(in.PushToken) > 1000 || strings.ContainsAny(in.PushToken, " \t\r\n"):
		writeErr(w, http.StatusBadRequest, "invalid_request", "push_token は受け手が出した値（16 文字以上）")
		return
	case in.Audience == "" || len(in.Audience) > 500:
		writeErr(w, http.StatusBadRequest, "invalid_request", "audience が要る")
		return
	}
	ctx := r.Context()
	if rs, err := s.Store.ListSSFReceivers(ctx, org); err != nil {
		writeStoreErr(w, err)
		return
	} else if len(rs) >= maxSSFReceiversPerOrg {
		writeErr(w, http.StatusConflict, "too_many", "受け手は 1 つの組織に 5 つまで")
		return
	}
	x := core.SSFReceiver{ID: core.NewID("ssr"), OrgID: org, Name: in.Name, URL: in.URL, PushToken: in.PushToken, Audience: in.Audience, CreatedAt: s.Clock.Now()}
	if err := s.Store.CreateSSFReceiver(ctx, x); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "ssf_receiver.create", x.ID)
	writeJSON(w, 201, ssfReceiverJSON(x))
}

func (s *Server) deleteSSFReceiver(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.ssfReady(w) {
		return
	}
	if err := s.Store.DeleteSSFReceiver(r.Context(), org, r.PathValue("rid")); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "ssf_receiver.delete", r.PathValue("rid"))
	w.WriteHeader(http.StatusNoContent)
}
