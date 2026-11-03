package adminapi

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/imohiyoko/mdm/pki"
)

// 端末の Wi-Fi などの証明書（EAP-TLS）。

func (s *Server) networkReady(w http.ResponseWriter) bool {
	if s.Network == nil {
		writeErr(w, http.StatusNotImplemented, "radius_not_configured", "設定の radius（Wi-Fi の認証のサーバー）が無い")
		return false
	}
	return true
}

// POST /v1/devices/{id}/network-cert は端末に証明書を発行する。鍵を含む PKCS#12 はこのときだけ返す。
// 既定で前の証明書を取り消す（keep_previous なら残す。入れ替えのあいだだけ使う）。
func (s *Server) issueNetworkCert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		KeepPrevious bool `json:"keep_previous"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &in) {
		return
	}
	if !s.networkReady(w) {
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	iss, err := s.Network.Issue(r.Context(), d.ID, !in.KeepPrevious)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, d.OrgID, "device.network_cert.issue", d.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"fingerprint": pki.Fingerprint(iss.Cert),
		"not_after":   iss.Cert.NotAfter,
		"pkcs12":      base64.StdEncoding.EncodeToString(iss.PKCS12),
		"password":    iss.Password,
		"ca_cert":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Network.CA.Cert.Raw})),
		"server_name": s.Network.ServerName,
		"identity":    d.ID,
	})
}

func (s *Server) listNetworkCerts(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, false)
	if !ok {
		return
	}
	cs, err := s.Store.ListNetworkCerts(r.Context(), d.ID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	type c struct {
		Fingerprint string    `json:"fingerprint"`
		NotAfter    time.Time `json:"not_after"`
		CreatedAt   time.Time `json:"created_at"`
	}
	out := []c{}
	for _, x := range cs {
		out = append(out, c{x.Fingerprint, x.NotAfter, x.CreatedAt})
	}
	writeJSON(w, 200, map[string]any{"certs": out})
}

// DELETE /v1/devices/{id}/network-cert は端末の証明書をすべて取り消す。次の接続から Wi-Fi に入れなくなる。
func (s *Server) revokeNetworkCerts(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	if _, err := s.Store.DeleteNetworkCerts(r.Context(), d.ID); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, d.OrgID, "device.network_cert.revoke", d.ID)
	w.WriteHeader(http.StatusNoContent)
}
