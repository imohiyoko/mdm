package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func TestCAOnlyForClients(t *testing.T) {
	ca, err := NewCA("t", 2048)
	if err != nil {
		t.Fatal(err)
	}
	// 認証局はクライアント認証にしか使えない（サーバーの証明書に使われないように）。
	if len(ca.Cert.ExtKeyUsage) != 1 || ca.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal(ca.Cert.ExtKeyUsage)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	req, _ := x509.ParseCertificateRequest(csr)
	if _, err := ca.Sign(req, "dev", time.Now(), time.Hour); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestNetworkCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateNetworkCA(dir+"/c.pem", dir+"/k.pem", "net", "radius.home.example")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	srv, err := ca.IssueServer(&key.PublicKey, "radius.home.example", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, DNSName: "radius.home.example", CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	// ほかの名前のサーバーの証明書は、作れても確かめで通らない（名前の制約）。
	other, err := ca.IssueServer(&key.PublicKey, "www.bank.example", now, time.Hour)
	if err == nil {
		if _, err := other.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.bank.example", CurrentTime: now}); err == nil {
			t.Fatal("name constraint not enforced")
		}
	}
	dev, err := ca.Issue(&key.PublicKey, "dev_1", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ca.Verify(dev, now); err != nil || id != "dev_1" {
		t.Fatal(id, err)
	}
	if _, err := LoadOrCreateNetworkCA(dir+"/c.pem", dir+"/k.pem", "net", "radius.other.example"); err == nil {
		t.Fatal("server name changed but accepted")
	}
}
