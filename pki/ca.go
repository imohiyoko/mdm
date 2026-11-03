// Package pki は端末の証明書を発行する認証局。
package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"
)

// CA は端末の証明書を発行する認証局。端末はこの証明書で管理のサーバーに自分を示す（TLS のクライアント証明書）。
//
// この認証局の証明書は端末の信頼する証明書に入るので、用途をクライアント認証だけに絞る。
// こうすると、鍵が漏れてもサーバーの証明書（なりすまし）には使えない（Windows は用途を上の証明書から引き継いで確かめる）。
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// LoadOrCreateCA は certPath と keyPath の認証局を読む。どちらも無ければ name で作って書く。
func LoadOrCreateCA(certPath, keyPath, name string) (*CA, error) {
	return loadOrCreate(certPath, keyPath, func() (*CA, error) { return NewCA(name, 3072) })
}

// LoadOrCreateNetworkCA は Wi-Fi などのネットワークの認証局（NewNetworkCA）を読む。無ければ作って書く。
// 読んだ認証局が serverName の証明書を発行できなければ（名前を変えたとき）、誤りを返す。
func LoadOrCreateNetworkCA(certPath, keyPath, name, serverName string) (*CA, error) {
	ca, err := loadOrCreate(certPath, keyPath, func() (*CA, error) { return NewNetworkCA(name, serverName) })
	if err != nil {
		return nil, err
	}
	if !slices.Contains(ca.Cert.PermittedDNSDomains, serverName) {
		return nil, fmt.Errorf("pki: %s の認証局は %s の証明書を発行できない（名前を変えたら、認証局を作り直して端末に配り直す）", certPath, serverName)
	}
	return ca, nil
}

func loadOrCreate(certPath, keyPath string, create func() (*CA, error)) (*CA, error) {
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if errors.Is(err1, os.ErrNotExist) && errors.Is(err2, os.ErrNotExist) {
		ca, err := create()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(ca.Key)}), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o644); err != nil {
			return nil, err
		}
		return ca, nil
	}
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("pki: 認証局の PEM が読めない")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("pki: 認証局の鍵が使えない")
	}
	return &CA{Cert: cert, Key: signer}, nil
}

func mustPKCS8(k crypto.Signer) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

// NewCA は新しい認証局を作る（20 年）。
func NewCA(name string, bits int) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key}, err
}

// NewNetworkCA は Wi-Fi などのネットワークの認証局を作る（20 年）。端末の証明書（クライアント認証）と、
// 認証のサーバー（RADIUS）の証明書を発行する。
//
// 端末はこの認証局をサーバーの確かめに使うので、信頼する証明書に入る。鍵が漏れたときにほかのサイトのなりすましに
// 使えないよう、発行できるサーバーの名前を serverName だけに絞り（名前の制約）、IP アドレスの名前を禁じる。
func NewNetworkCA(name, serverName string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	_, all4, _ := net.ParseCIDR("0.0.0.0/0")
	_, all6, _ := net.ParseCIDR("::/0")
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                randSerial(),
		Subject:                     pkix.Name{CommonName: name},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(20, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{serverName},
		ExcludedIPRanges:            []*net.IPNet{all4, all6},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key}, err
}

// IssueServer は認証のサーバーの証明書を発行する。
func (ca *CA) IssueServer(pub any, dnsName string, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// Sign は端末の証明書の要求（CSR）に署名する。名前（CN）は MDM の端末の ID にする。
func (ca *CA) Sign(csr *x509.CertificateRequest, deviceID string, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: 証明書の要求の署名が正しくない: %w", err)
	}
	return ca.Issue(csr.PublicKey, deviceID, now, validity)
}

// Issue は公開鍵 pub に端末の証明書を発行する。
func (ca *CA) Issue(pub any, deviceID string, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("pki: 鍵が短い")
		}
	default:
		return nil, errors.New("pki: RSA の鍵だけを受け付ける")
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Verify は端末の証明書がこの認証局のもので、期限の中かを確かめ、端末の ID（CN）を返す。
func (ca *CA) Verify(cert *x509.Certificate, now time.Time) (string, error) {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", err
	}
	if cert.Subject.CommonName == "" {
		return "", errors.New("pki: 証明書に端末の ID が無い")
	}
	return cert.Subject.CommonName, nil
}

// Fingerprint は証明書の SHA-256（16 進の小文字）。端末の証明書を覚えるのに使う。
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
