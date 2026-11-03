// Package network は Wi-Fi などのネットワークに入るための端末の証明書を発行・取り消す。
package network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/pki"
)

// Service は端末の証明書を発行する。
type Service struct {
	Store core.Store
	Clock core.Clock
	CA    *pki.CA
	// ServerName は認証のサーバー（RADIUS）の名前。端末はこの名前でサーバーを確かめる。
	ServerName string
	// Validity は端末の証明書の期間（既定 2 年）。
	Validity time.Duration
}

// Issued は発行した証明書。鍵は MDM に残さないので、ここでしか取り出せない。
type Issued struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
	// PKCS12 は鍵と証明書と認証局をまとめたもの（パスワードは Password）。
	PKCS12   []byte
	Password string
}

// Issue は端末に新しい証明書を発行する。replace なら、前の証明書を取り消す。
func (s *Service) Issue(ctx context.Context, deviceID string, replace bool) (Issued, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Issued{}, err
	}
	validity := s.Validity
	if validity == 0 {
		validity = 2 * 365 * 24 * time.Hour
	}
	now := s.Clock.Now()
	cert, err := s.CA.Issue(&key.PublicKey, deviceID, now, validity)
	if err != nil {
		return Issued{}, err
	}
	pw := make([]byte, 12)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw)
	// 古い端末（iOS・Windows・Android）でも読めるように、昔からの暗号（3DES）で包む。
	p12, err := pkcs12.LegacyDES.Encode(key, cert, []*x509.Certificate{s.CA.Cert}, pass)
	if err != nil {
		return Issued{}, err
	}
	if replace {
		if _, err := s.Store.DeleteNetworkCerts(ctx, deviceID); err != nil {
			return Issued{}, err
		}
	}
	if err := s.Store.PutNetworkCert(ctx, core.NetworkCert{Fingerprint: pki.Fingerprint(cert), DeviceID: deviceID, NotAfter: cert.NotAfter, CreatedAt: now}); err != nil {
		return Issued{}, err
	}
	return Issued{Cert: cert, Key: key, PKCS12: p12, Password: pass}, nil
}

// Revoke は端末の証明書をすべて取り消す。
func (s *Service) Revoke(ctx context.Context, deviceID string) (int64, error) {
	return s.Store.DeleteNetworkCerts(ctx, deviceID)
}
