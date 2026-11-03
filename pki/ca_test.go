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
