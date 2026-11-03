package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Pusher は端末を起こす通知を送る。端末は通知を受けると、サーバーに命令を取りに来る。
type Pusher interface {
	Push(ctx context.Context, token []byte, pushMagic string) error
}

// APNs は Apple の通知の仕組み（HTTP/2）。MDM の通知用の証明書で接続する。
type APNs struct {
	// BaseURL は空なら https://api.push.apple.com。
	BaseURL string
	Topic   string
	HTTP    *http.Client
}

var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// NewAPNs は MDM の通知用の証明書（Apple Push Certificates Portal で取ったもの）で APNs のクライアントを作る。
// Topic は証明書の UID（com.apple.mgmt.External.…）。
func NewAPNs(cert tls.Certificate) (*APNs, error) {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	topic := pushTopic(leaf)
	if topic == "" {
		return nil, errors.New("apple: 通知用の証明書に UID（topic）が無い。MDM 用の証明書か確かめる")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("apple: 通知用の証明書の期限が切れている（%s）。Apple Push Certificates Portal で更新する", leaf.NotAfter.Format("2006-01-02"))
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	return &APNs{Topic: topic, HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

// Push は端末に MDM の通知を送る。
func (a *APNs) Push(ctx context.Context, token []byte, pushMagic string) error {
	base := a.BaseURL
	if base == "" {
		base = "https://api.push.apple.com"
	}
	body, _ := json.Marshal(map[string]string{"mdm": pushMagic})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+hex.EncodeToString(token), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("apns-topic", a.Topic)
	req.Header.Set("apns-push-type", "mdm")
	req.Header.Set("apns-priority", "10")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("apple: 通知に失敗した: %d %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}
