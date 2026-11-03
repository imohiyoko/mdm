package adminapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/pki"
)

// RadSec はルーターとの RADIUS を TLS で守る設定（ADR 0015）。
type RadSec struct {
	// CA はルーターのクライアント証明書を発行する認証局（端末の認証局とは別）。
	CA *pki.CA
	// Address はルーターに設定させる MDM の RadSec の入り口（host:port）。
	Address string
}

const radsecCertValidity = 3 * 365 * 24 * time.Hour

// createRadSecClient は RadSec のルーターを登録し、ルーターの証明書と鍵を返す（このときだけ）。
func (s *Server) createRadSecClient(w http.ResponseWriter, r *http.Request, org, name, address string) {
	if s.RadSec == nil {
		writeErr(w, http.StatusNotImplemented, "not_configured", "このサーバーでは RadSec を使わない（設定の radius.radsec_listen が無い）")
		return
	}
	if address != "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "RadSec のルーターに address は要らない（証明書で見分ける）")
		return
	}
	ctx := r.Context()
	radiusMu.Lock()
	defer radiusMu.Unlock()
	all, err := s.Store.ListRADIUSClients(ctx, org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if len(all) >= maxRADIUSClientsPerOrg {
		writeErr(w, http.StatusConflict, "too_many", "ルーターは 1 つの組織に 20 台まで")
		return
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	id := core.NewID("rdc")
	now := s.Clock.Now()
	cert, err := s.RadSec.CA.Issue(&key.PublicKey, id, now, radsecCertValidity)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	c := core.RADIUSClient{ID: id, OrgID: org, Name: name, Secret: "", CertFingerprint: pki.Fingerprint(cert), CreatedAt: now}
	if err := s.Store.CreateRADIUSClient(ctx, c); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "radius_client.create", c.ID)
	s.radiusChanged()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	out := radiusClientJSON(c)
	out["client_cert"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	out["client_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	// ルーターが MDM を確かめるための認証局（端末の Wi-Fi の設定に入れるものと同じ）と名前。
	out["server_ca"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Network.CA.Cert.Raw}))
	out["server_name"] = s.Network.ServerName
	out["radsec_address"] = s.RadSec.Address
	out["not_after"] = cert.NotAfter
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, out)
}
