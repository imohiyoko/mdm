package radiusd

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

type radsecEnv struct {
	*env
	addr   string
	router tls.Certificate
	mu     sync.Mutex
	list   []Client
}

func (r *radsecEnv) set(cs ...Client) {
	r.mu.Lock()
	r.list = cs
	r.mu.Unlock()
	if err := r.srv.Refresh(context.Background()); err != nil {
		panic(err)
	}
}

func newRadSecEnv(t *testing.T) *radsecEnv {
	t.Helper()
	rca, err := pki.NewCA("mdm RadSec router CA", 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, err := rca.Issue(&key.PublicKey, "rdc_1", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := &radsecEnv{router: tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
	r.list = []Client{{Name: "org:org1/rdc_1", OrgIDs: []string{testkit.OrgID}, RadSecID: "rdc_1", RadSecFingerprint: pki.Fingerprint(cert)}}
	r.env = newEnv(t, func(s *Server) {
		s.Clients = nil
		s.RadSecCA = rca
		s.Dynamic = func(context.Context) ([]Client, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]Client(nil), r.list...), nil
		}
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", r.srv.RadSecTLS(rca))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.srv.ServeRadSec(ctx, ln) }()
	r.addr = ln.Addr().String()
	// newEnv の Serve が一覧を読むのを待たずに、ここで読む。
	r.set(r.list...)
	return r
}

func (r *radsecEnv) dial(t *testing.T, cert tls.Certificate) (*tls.Conn, error) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(r.ca.Cert)
	c, err := tls.Dial("tcp", r.addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: serverName})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, c.Handshake()
}

func TestRadSec(t *testing.T) {
	r := newRadSecEnv(t)
	conn, err := r.dial(t, r.router)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.ca.Cert)
	// 同じ接続で何度でも認証できる。
	for range 2 {
		if resp := supplicantOver(t, conn, RadSecSecret, r.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessAccept {
			t.Fatal(resp.Code)
		}
	}
}

// 共有の秘密が "radsec" でないと答えない（RFC 6614）。
func TestRadSecWrongSecret(t *testing.T) {
	r := newRadSecEnv(t)
	conn, err := r.dial(t, r.router)
	if err != nil {
		t.Fatal(err)
	}
	wrong := []byte("other")
	req := radius.New(radius.CodeAccessRequest, wrong)
	_ = rfc2865.UserName_SetString(req, "dev1")
	_ = rfc2869.EAPMessage_Set(req, eapPacket{Code: eapResponse, ID: 1, Type: eapTypeIdentity, Data: []byte("dev1")}.encode())
	_ = rfc2869.MessageAuthenticator_Set(req, make([]byte, 16))
	raw, _ := req.MarshalBinary()
	m := hmac.New(md5.New, wrong)
	m.Write(raw)
	_ = rfc2869.MessageAuthenticator_Set(req, m.Sum(nil))
	b, _ := req.Encode()
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("answered")
	}
}

// 端末の証明書（ネットワークの認証局）や、知らない認証局の証明書ではつなげない。
func TestRadSecRejectsOtherCerts(t *testing.T) {
	r := newRadSecEnv(t)
	// TLS 1.3 ではクライアントの握手は先に終わり、サーバーに切られるので、読むと失敗する。
	if c, err := r.dial(t, r.client); err == nil {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("device certificate accepted")
		}
	}
	other, _ := pki.NewCA("other", 2048)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := other.Issue(&key.PublicKey, "rdc_1", time.Now(), time.Hour)
	c, err := r.dial(t, tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key})
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("foreign CA accepted")
		}
	}
}

// 消したルーター・作り直す前の証明書では、その後の要求に答えない。
func TestRadSecDeletedRouter(t *testing.T) {
	r := newRadSecEnv(t)
	conn, err := r.dial(t, r.router)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.ca.Cert)
	if resp := supplicantOver(t, conn, RadSecSecret, r.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessAccept {
		t.Fatal(resp.Code)
	}
	c := r.list[0]
	c.RadSecFingerprint = "00"
	r.set(c) // 証明書を作り直した
	req := radius.New(radius.CodeAccessRequest, RadSecSecret)
	b, _ := req.Encode()
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("answered after the certificate was replaced")
	}
	conn2, err := r.dial(t, r.router)
	if err == nil {
		_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn2.Write(b); err == nil {
			if _, err := conn2.Read(make([]byte, 1)); err == nil {
				t.Fatal("answered on a new connection")
			}
		}
	}
}

// 握手をしない接続で 1 つの接続元が枠を使い切っても、上限を超えた分はすぐ切られる。
func TestRadSecPerIPLimit(t *testing.T) {
	r := newRadSecEnv(t)
	var idle []net.Conn
	t.Cleanup(func() {
		for _, c := range idle {
			_ = c.Close()
		}
	})
	for range maxRadSecConnsPerIP {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(200 * time.Millisecond) // 受け付けを待つ
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("over-limit connection was kept", err)
	}
	// 枠を返すと、またつなげる。
	for _, c := range idle {
		_ = c.Close()
	}
	idle = nil
	time.Sleep(200 * time.Millisecond)
	conn, err := r.dial(t, r.router)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.ca.Cert)
	if resp := supplicantOver(t, conn, RadSecSecret, r.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessAccept {
		t.Fatal(resp.Code)
	}
}
