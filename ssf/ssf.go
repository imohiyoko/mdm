// Package ssf は OpenID Shared Signals Framework（SSF）の送信側。端末の準拠の状態の変化を、
// CAEP の device-compliance-change の Security Event Token（SET、RFC 8417）にして、IAM などの受け手に push（RFC 8935）で送る。
package ssf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// EventDeviceComplianceChange は CAEP の device-compliance-change。
const EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"

// 準拠の状態（CAEP）。
const (
	StatusCompliant    = "compliant"
	StatusNotCompliant = "not-compliant"
)

// Signer は SET に署名する鍵（ES256）。
type Signer struct {
	Key *ecdsa.PrivateKey
	KID string
}

// NewSigner は鍵から Signer を作る。kid は公開鍵の JWK のサムプリント（RFC 7638）。
func NewSigner(key *ecdsa.PrivateKey) (*Signer, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("ssf: 署名の鍵は P-256 にする")
	}
	jwk := publicJWK(&key.PublicKey, "")
	b, _ := json.Marshal(map[string]string{"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
	sum := sha256.Sum256(b)
	return &Signer{Key: key, KID: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// LoadOrCreateSigner は PEM の鍵を読む。無ければ作って保存する（0600）。
func LoadOrCreateSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		return NewSigner(key)
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("ssf: %s は PEM ではない", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		ek, err2 := x509.ParseECPrivateKey(blk.Bytes)
		if err2 != nil {
			return nil, err
		}
		k = ek
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ssf: 署名の鍵は ECDSA（P-256）にする")
	}
	return NewSigner(key)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

func publicJWK(pub *ecdsa.PublicKey, kid string) map[string]string {
	ecdh, _ := pub.ECDH()
	raw := ecdh.Bytes() // 0x04 || X || Y
	j := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:65])}
	if kid != "" {
		j["kid"], j["use"], j["alg"] = kid, "sig", "ES256"
	}
	return j
}

// JWKS は公開鍵の JWK Set（受け手が SET を確かめるのに使う）。
func (s *Signer) JWKS() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(&s.Key.PublicKey, s.KID)}})
	return b
}

// Sign は claims を JWS（ES256、typ secevent+jwt）にする。
func (s *Signer) Sign(claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "secevent+jwt", "kid": s.KID})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(append(pad32(r), pad32(ss)...)), nil
}

// Public は署名を確かめる公開鍵（テスト用）。
func (s *Signer) Public() crypto.PublicKey { return &s.Key.PublicKey }

// ComplianceChange は device-compliance-change の中身。
type ComplianceChange struct {
	Email     string // 利用者（IAM の確認済みのメールアドレス）
	DeviceID  string // MDM の端末の ID（不透明な参照）
	OrgID     string // 端末の組織（送り先を選ぶのに使う。SET には入れない）
	Current   string
	Previous  string // 空なら初めての判定
	ChangedAt time.Time
	// Reason は管理者向けの理由（英語）。
	Reason string
}

// ComplianceSET は device-compliance-change の SET の claims を作る。
func ComplianceSET(issuer, audience string, c ComplianceChange, now time.Time) map[string]any {
	ev := map[string]any{"current_status": c.Current, "event_timestamp": c.ChangedAt.Unix(), "initiating_entity": "policy"}
	if c.Previous != "" {
		ev["previous_status"] = c.Previous
	}
	if c.Reason != "" {
		ev["reason_admin"] = map[string]string{"en": c.Reason}
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	return map[string]any{
		"iss": issuer, "aud": audience, "iat": now.Unix(), "jti": b64(jti),
		"sub_id": map[string]any{
			"format": "complex",
			"user":   map[string]string{"format": "email", "email": c.Email},
			"device": map[string]string{"format": "opaque", "id": c.DeviceID},
		},
		"events": map[string]any{EventDeviceComplianceChange: ev},
	}
}

// Configuration は /.well-known/ssf-configuration（SSF 1.0 の 6 章）。受け手の側のストリームの管理は持たず、push だけで送る。
func Configuration(issuer string) []byte {
	b, _ := json.Marshal(map[string]any{
		"spec_version":               "1_0",
		"issuer":                     issuer,
		"jwks_uri":                   issuer + "/.well-known/jwks.json",
		"delivery_methods_supported": []string{"urn:ietf:rfc:8935"},
		"default_subjects":           "NONE",
	})
	return b
}
