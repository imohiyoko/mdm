package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestOrgPushCert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	topic := "com.apple.mgmt.External.org-1"
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidUID, Value: topic}}},
		NotBefore: e.clock.Now().Add(-time.Hour), NotAfter: e.clock.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	if _, got, _, err := ParsePushCert(certPEM, keyPEM, e.clock.Now()); err != nil || got != topic {
		t.Fatal(got, err)
	}
	if err := e.store.PutApplePush(ctx, core.ApplePush{OrgID: testkit.OrgID, Topic: topic, CertPEM: string(certPEM), KeyPEM: string(keyPEM), UpdatedAt: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	orgPush := &fakePusher{}
	made := 0
	e.svc.NewPusher = func(tls.Certificate) (Pusher, error) { made++; return orgPush, nil }

	// 登録のプロファイルには組織の topic が入る。
	e.topic = topic
	c := e.enroll(t)
	// 端末の言う topic が組織のものと違えば断る。
	if code, _ := e.put(t, c, PathCheckIn, map[string]any{"MessageType": "Authenticate", "UDID": "UDID-1", "Topic": "com.apple.mgmt.External.test"}); code != 401 {
		t.Fatalf("違う topic: %d", code)
	}
	if code, _ := e.put(t, c, PathCheckIn, map[string]any{"MessageType": "Authenticate", "UDID": "UDID-1", "Topic": topic}); code != 200 {
		t.Fatalf("authenticate: %d", code)
	}
	if code, _ := e.put(t, c, PathCheckIn, map[string]any{"MessageType": "TokenUpdate", "UDID": "UDID-1", "Token": []byte{1, 2, 3}, "PushMagic": "magic-1"}); code != 200 {
		t.Fatalf("token update: %d", code)
	}
	// 通知は組織の証明書で送る（サーバーの設定の証明書は使わない）。作った Pusher は使い回す。
	m, _ := e.store.GetManaged(ctx, e.dev.ID)
	for range 2 {
		if err := e.svc.push(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if orgPush.count() < 2 || e.push.count() != 0 || made != 1 {
		t.Fatalf("org=%d server=%d made=%d", orgPush.count(), e.push.count(), made)
	}
	if ok, err := e.svc.HasEnrolled(ctx, testkit.OrgID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := e.svc.HasEnrolled(ctx, "org-other"); ok {
		t.Fatal("ほかの組織")
	}
}
