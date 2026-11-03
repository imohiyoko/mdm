package adminapi_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/apple"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

// pushCertPEM は Apple の通知用の証明書に似せた証明書（UID に topic）。
func pushCertPEM(t *testing.T, pub any, topic string, notAfter time.Time) string {
	t.Helper()
	signer, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "APSP:" + topic, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic}}},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func keyPEM(k *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestApplePushPerOrg(t *testing.T) {
	ca, err := pki.NewCA("t", 2048)
	if err != nil {
		t.Fatal(err)
	}
	vendorKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	var svc *apple.Service
	c, store, clock := newServer(t, func(s *adminapi.Server) {
		// サーバーの設定には通知用の証明書が無い。組織ごとに入れる。
		svc = &apple.Service{Store: s.Store, Engine: s.Engine, Clock: s.Clock, CA: ca, BaseURL: "https://mdm.example",
			NewPusher: func(tls.Certificate) (apple.Pusher, error) { return &countPusher{}, nil }}
		s.Apple = svc
	})
	a := c.as("mdm_org_admin")
	base := "/v1/orgs/" + testkit.OrgID + "/apple/push"
	notAfter := clock.Now().Add(300 * 24 * time.Hour)

	var st map[string]any
	if code := a.do("GET", base, nil, &st); code != 200 || st["source"] != "none" || st["vendor_signing"] != false {
		t.Fatalf("get: %d %v", code, st)
	}
	var dev struct{ Device map[string]any }
	a.do("POST", "/v1/devices", map[string]any{"name": "iPhone", "platform": "ios"}, &dev)
	devID := dev.Device["id"].(string)
	if code := a.do("POST", "/v1/devices/"+devID+"/enroll", map[string]any{}, nil); code != 409 {
		t.Fatalf("証明書が無いと登録できない: %d", code)
	}

	// CSR を作り、Apple が返した証明書（ここでは作ったもの）を鍵なしで入れる。
	var csrOut map[string]any
	if code := a.do("POST", base+"/csr", nil, &csrOut); code != 201 || csrOut["push_cert_request"] != nil {
		t.Fatalf("csr: %d %v", code, csrOut)
	}
	blk, _ := pem.Decode([]byte(csrOut["csr"].(string)))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	topic := "com.apple.mgmt.External.11111111-2222-3333-4444-555555555555"
	cert := pushCertPEM(t, csr.PublicKey, topic, notAfter)
	if a.do("GET", base, nil, &st); st["pending_csr"] != true {
		t.Fatalf("pending: %v", st)
	}
	var put map[string]any
	if code := a.do("PUT", base, map[string]any{"cert": cert}, &put); code != 200 || put["topic"] != topic {
		t.Fatalf("put: %d %v", code, put)
	}
	if a.do("GET", base, nil, &st); st["source"] != "org" || st["topic"] != topic || st["pending_csr"] != false {
		t.Fatalf("after put: %v", st)
	}
	if code := a.do("POST", "/v1/devices/"+devID+"/enroll", map[string]any{}, nil); code != 200 {
		t.Fatalf("証明書を入れたら登録できる: %d", code)
	}

	// 確かめ：鍵と組でない・MDM のものでない・期限切れ。
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey := keyPEM(other)
	for name, body := range map[string]map[string]any{
		"鍵と組でない":     {"cert": pushCertPEM(t, csr.PublicKey, topic, notAfter), "key": otherKey},
		"MDM のものでない": {"cert": pushCertPEM(t, &other.PublicKey, "com.example.app", notAfter), "key": otherKey},
		"期限切れ":       {"cert": pushCertPEM(t, &other.PublicKey, topic, clock.Now().Add(-time.Hour)), "key": otherKey},
		"鍵が無い":       {"cert": pushCertPEM(t, &other.PublicKey, topic, notAfter)},
	} {
		if code := a.do("PUT", base, body, nil); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}

	// 端末を登録したら、topic の違う証明書（別の Apple ID）には変えられない。同じ topic での更新はできる。
	ctx := context.Background()
	if err := store.PutManaged(ctx, core.Managed{DeviceID: devID, Provider: apple.Provider, State: core.ManagedActive, CertFingerprints: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	otherTopic := "com.apple.mgmt.External.99999999-2222-3333-4444-555555555555"
	if code := a.do("PUT", base, map[string]any{"cert": pushCertPEM(t, &other.PublicKey, otherTopic, notAfter), "key": otherKey}, nil); code != 409 {
		t.Fatalf("topic が変わる: %d", code)
	}
	if code := a.do("PUT", base, map[string]any{"cert": pushCertPEM(t, &other.PublicKey, topic, notAfter.Add(365*24*time.Hour)), "key": otherKey}, nil); code != 200 {
		t.Fatalf("同じ topic で更新: %d", code)
	}
	if code := a.do("DELETE", base, nil, nil); code != 409 {
		t.Fatalf("端末があると消せない: %d", code)
	}

	// ほかの組織・見るだけの人。
	var o map[string]any
	c.do("POST", "/v1/orgs", map[string]any{"name": "ほか", "kind": "company"}, &o)
	if code := a.do("GET", "/v1/orgs/"+o["id"].(string)+"/apple/push", nil, nil); code != 404 {
		t.Fatalf("ほかの組織: %d", code)
	}
	if code := c.as("mdm_org_viewer").do("POST", base+"/csr", nil, nil); code != 403 {
		t.Fatalf("見るだけ: %d", code)
	}
	if code := c.as("mdm_org_viewer").do("GET", base, nil, nil); code != 200 {
		t.Fatalf("見るだけでも状態は見られる: %d", code)
	}

	// ベンダーの証明書があれば、CSR に署名して Apple に上げるファイルを返す。
	vendorChain := pushCertPEM(t, &vendorKey.PublicKey, "vendor", notAfter)
	svc.Vendor = &apple.Vendor{ChainPEM: []byte(vendorChain), Key: vendorKey}
	if code := a.do("POST", base+"/csr", nil, &csrOut); code != 201 {
		t.Fatalf("csr with vendor: %d", code)
	}
	raw, err := base64.StdEncoding.DecodeString(csrOut["push_cert_request"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var req map[string]string
	if _, err := plist.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	csrDER, _ := base64.StdEncoding.DecodeString(req["PushCertRequestCSR"])
	sig, _ := base64.StdEncoding.DecodeString(req["PushCertSignature"])
	sum := sha256.Sum256(csrDER)
	if err := rsa.VerifyPKCS1v15(&vendorKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil || req["PushCertCertificateChain"] != vendorChain {
		t.Fatalf("vendor signature: %v %v", err, req)
	}
	// CSR を作り直しても、今の証明書はそのまま使う。
	if a.do("GET", base, nil, &st); st["source"] != "org" || st["pending_csr"] != true {
		t.Fatalf("csr のあと: %v", st)
	}
}
