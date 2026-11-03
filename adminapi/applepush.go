package adminapi

import (
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/mdm/apple"
	"github.com/imohiyoko/mdm/core"
)

// 組織の iPhone・Mac の通知用の証明書（ADR 0012）。

func (s *Server) getApplePush(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canRead(w, r, org) || !s.appleReady(w) {
		return
	}
	if _, err := s.Store.GetOrg(r.Context(), org); err != nil {
		writeStoreErr(w, err)
		return
	}
	p, err := s.Store.GetApplePush(r.Context(), org)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		writeStoreErr(w, err)
		return
	}
	out := map[string]any{"source": "none", "pending_csr": p.PendingKeyPEM != "", "vendor_signing": s.Apple.Vendor != nil}
	switch {
	case p.CertPEM != "":
		out["source"], out["topic"], out["not_after"] = "org", p.Topic, p.NotAfter
	case s.Apple.Topic != "":
		out["source"], out["topic"] = "server", s.Apple.Topic
	}
	writeJSON(w, 200, out)
}

func (s *Server) createApplePushCSR(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.appleReady(w) {
		return
	}
	if _, err := s.Store.GetOrg(r.Context(), org); err != nil {
		writeStoreErr(w, err)
		return
	}
	p, err := s.Store.GetApplePush(r.Context(), org)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		writeStoreErr(w, err)
		return
	}
	keyPEM, csr, err := apple.NewPushKey()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	out := map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	if s.Apple.Vendor != nil {
		req, err := s.Apple.Vendor.SignPushCSR(csr)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		out["push_cert_request"] = string(req)
	}
	// 今の証明書はそのまま使い続ける。新しい証明書が届いたら入れ替える。
	p.OrgID, p.PendingKeyPEM, p.UpdatedAt = org, string(keyPEM), s.Clock.Now()
	if err := s.Store.PutApplePush(r.Context(), p); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "apple_push.csr", org)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) putApplePush(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.appleReady(w) {
		return
	}
	var in struct {
		Cert string `json:"cert"`
		// Key を省いたら、CSR を作ったときの鍵を使う。
		Key string `json:"key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	if _, err := s.Store.GetOrg(ctx, org); err != nil {
		writeStoreErr(w, err)
		return
	}
	p, err := s.Store.GetApplePush(ctx, org)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		writeStoreErr(w, err)
		return
	}
	key := in.Key
	if key == "" {
		key = p.PendingKeyPEM
	}
	if key == "" {
		writeErr(w, 400, "invalid_request", "key が要る（先に csr を作ったなら省ける）")
		return
	}
	now := s.Clock.Now()
	_, topic, notAfter, err := apple.ParsePushCert([]byte(in.Cert), []byte(key), now)
	if err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	// topic が変わると、登録した端末は通知を受けられなくなる（Apple ID ごとに topic が違う）。同じ Apple ID で更新する。
	cur, _, err := s.Apple.PushTopic(ctx, org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if cur != "" && cur != topic {
		enrolled, err := s.Apple.HasEnrolled(ctx, org)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		if enrolled {
			writeErr(w, http.StatusConflict, "topic_changed", "登録した端末と topic が違う。前と同じ Apple ID で証明書を更新する（別の Apple ID にするなら、先に端末の管理を外す）")
			return
		}
	}
	p = core.ApplePush{OrgID: org, Topic: topic, CertPEM: in.Cert, KeyPEM: key, NotAfter: notAfter, UpdatedAt: now}
	if err := s.Store.PutApplePush(ctx, p); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "apple_push.put", topic)
	writeJSON(w, 200, map[string]any{"source": "org", "topic": topic, "not_after": notAfter.UTC().Format(time.RFC3339)})
}

func (s *Server) deleteApplePush(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("id")
	if !canWrite(w, r, org) || !s.appleReady(w) {
		return
	}
	ctx := r.Context()
	enrolled, err := s.Apple.HasEnrolled(ctx, org)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if enrolled {
		writeErr(w, http.StatusConflict, "conflict", "管理している iPhone・Mac がある（先に管理を外す）")
		return
	}
	if err := s.Store.DeleteApplePush(ctx, org); err != nil {
		writeStoreErr(w, err)
		return
	}
	s.audit(r, org, "apple_push.delete", org)
	w.WriteHeader(http.StatusNoContent)
}
