package apple

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/imohiyoko/mdm/core"
)

// 組織ごとの通知用の証明書。
//
// Apple の MDM の通知用の証明書は、使う組織の Apple ID で Apple Push Certificates Portal から取る。取るには
// MDM の提供者（ベンダー）が署名した証明書の要求（CSR）が要る。サーバーにベンダーの証明書があれば、MDM が鍵を作って
// 要求に署名し、組織の管理者はそれを Apple のサイトに上げて、返ってきた証明書を MDM に戻すだけでよい。
// ベンダーの証明書が無ければ、組織の管理者は自分で取った証明書と鍵を上げる。

// pushTopic は通知用の証明書の UID（topic）。
func pushTopic(leaf *x509.Certificate) string {
	for _, n := range leaf.Subject.Names {
		if n.Type.Equal(oidUID) {
			s, _ := n.Value.(string)
			return s
		}
	}
	return ""
}

// ParsePushCert は通知用の証明書と鍵（PEM）を確かめ、topic と期限を返す。
func ParsePushCert(certPEM, keyPEM []byte, now time.Time) (tls.Certificate, string, time.Time, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return cert, "", time.Time{}, fmt.Errorf("証明書と鍵が読めないか、組になっていない: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, "", time.Time{}, err
	}
	topic := pushTopic(leaf)
	if !strings.HasPrefix(topic, "com.apple.mgmt.") {
		return cert, "", time.Time{}, errors.New("MDM の通知用の証明書ではない（UID が com.apple.mgmt. で始まらない）")
	}
	if !now.Before(leaf.NotAfter) {
		return cert, "", time.Time{}, fmt.Errorf("証明書の期限が切れている（%s）", leaf.NotAfter.Format("2006-01-02"))
	}
	return cert, topic, leaf.NotAfter, nil
}

// NewPushKey は通知用の証明書の鍵と、Apple に出す証明書の要求（CSR、DER）を作る。
func NewPushKey() (keyPEM []byte, csrDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "MDM Push"}}, key)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), csrDER, nil
}

// Vendor は MDM の提供者の証明書（Apple Developer で取る MDM CSR の証明書）。組織の CSR に署名する。
type Vendor struct {
	// ChainPEM はベンダーの証明書・Apple の中間証明書（WWDR）・Apple のルート証明書の PEM をつなげたもの。
	ChainPEM []byte
	Key      crypto.Signer
}

// SignPushCSR は組織の CSR にベンダーの鍵で署名し、Apple Push Certificates Portal に上げるファイルの中身
// （plist を base64 にしたもの）を作る。
func (v *Vendor) SignPushCSR(csrDER []byte) ([]byte, error) {
	sum := sha256.Sum256(csrDER)
	sig, err := v.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	req := map[string]string{
		"PushCertRequestCSR":       base64.StdEncoding.EncodeToString(csrDER),
		"PushCertCertificateChain": string(v.ChainPEM),
		"PushCertSignature":        base64.StdEncoding.EncodeToString(sig),
	}
	b, err := plist.MarshalIndent(req, plist.XMLFormat, "\t")
	if err != nil {
		return nil, err
	}
	out := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(out, b)
	return out, nil
}

type cachedPusher struct {
	sum    [32]byte
	pusher Pusher
	topic  string
}

// pushFor は組織 orgID の端末に通知を送るもの。組織の証明書が無ければサーバーの設定の証明書（無ければ nil）。
func (s *Service) pushFor(ctx context.Context, orgID string) (Pusher, string, error) {
	p, err := s.Store.GetApplePush(ctx, orgID)
	if errors.Is(err, core.ErrNotFound) || err == nil && p.CertPEM == "" {
		return s.Pusher, s.Topic, nil
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(p.CertPEM + "\x00" + p.KeyPEM))
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if c, ok := s.pushers[orgID]; ok && c.sum == sum {
		return c.pusher, c.topic, nil
	}
	cert, err := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM))
	if err != nil {
		return nil, "", err
	}
	newPusher := s.NewPusher
	if newPusher == nil {
		newPusher = func(c tls.Certificate) (Pusher, error) { return NewAPNs(c) }
	}
	pu, err := newPusher(cert)
	if err != nil {
		return nil, "", err
	}
	if s.pushers == nil {
		s.pushers = map[string]cachedPusher{}
	}
	s.pushers[orgID] = cachedPusher{sum, pu, p.Topic}
	return pu, p.Topic, nil
}

// PushTopic は組織の端末が使う通知の topic と、組織の証明書か（false ならサーバーの設定のもの）。topic が空なら通知を送れない。
func (s *Service) PushTopic(ctx context.Context, orgID string) (string, bool, error) {
	p, err := s.Store.GetApplePush(ctx, orgID)
	if errors.Is(err, core.ErrNotFound) || err == nil && p.CertPEM == "" {
		return s.Topic, false, nil
	}
	return p.Topic, err == nil, err
}

// HasEnrolled は組織に Apple の管理の下の端末（登録の途中も含む）があるか。
func (s *Service) HasEnrolled(ctx context.Context, orgID string) (bool, error) {
	ms, err := s.Store.ListManaged(ctx, Provider)
	if err != nil {
		return false, err
	}
	for _, m := range ms {
		if m.State == core.ManagedRemoved {
			continue
		}
		d, err := s.Store.GetDevice(ctx, m.DeviceID)
		if errors.Is(err, core.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		if d.OrgID == orgID {
			return true, nil
		}
	}
	return false, nil
}
