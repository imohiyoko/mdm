package radiusd

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

const serverName = "radius.home.example"

var secret = []byte("testing123")

type env struct {
	store  core.Store
	ca     *pki.CA
	srv    *Server
	addr   string
	client tls.Certificate
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	store := testkit.Store(t)
	ca, err := pki.NewNetworkCA("net", serverName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePolicy(ctx, core.Policy{ID: "pol_default", Name: "d", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	if err := store.CreateDevice(ctx, core.Device{ID: "dev1", OrgID: testkit.OrgID, Name: "x", Platform: core.PlatformOther, FilterTokenHash: h1, DoTLabelHash: h2}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	skey, _ := rsa.GenerateKey(rand.Reader, 2048)
	scert, err := ca.IssueServer(&skey.PublicKey, serverName, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ckey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ccert, err := ca.Issue(&ckey.PublicKey, "dev1", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutNetworkCert(ctx, core.NetworkCert{Fingerprint: pki.Fingerprint(ccert), DeviceID: "dev1", NotAfter: ccert.NotAfter, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Store: store, Clock: core.SystemClock{}, CA: ca, TLSCert: tls.Certificate{Certificate: [][]byte{scert.Raw}, PrivateKey: skey},
		Clients: []Client{{Name: "ap", Prefix: netip.MustParsePrefix("127.0.0.0/8"), Secret: secret}}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(sctx, pc) }()
	return &env{store, ca, srv, pc.LocalAddr().String(), tls.Certificate{Certificate: [][]byte{ccert.Raw}, PrivateKey: ckey}}
}

// exchange は RADIUS の要求を 1 つ送って答えを受ける（Message-Authenticator を付ける）。
func exchange(t *testing.T, conn net.Conn, req *radius.Packet) *radius.Packet {
	t.Helper()
	_ = rfc2869.MessageAuthenticator_Set(req, make([]byte, 16))
	raw, _ := req.MarshalBinary()
	m := hmac.New(md5.New, secret)
	m.Write(raw)
	_ = rfc2869.MessageAuthenticator_Set(req, m.Sum(nil))
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !radius.IsAuthenticResponse(buf[:n], b, secret) {
		t.Fatal("response authenticator")
	}
	resp, err := radius.Parse(buf[:n], secret)
	if err != nil {
		t.Fatal(err)
	}
	if !validMessageAuthenticatorResponse(buf[:n], req.Authenticator, secret) {
		t.Fatal("response Message-Authenticator")
	}
	return resp
}

// validMessageAuthenticatorResponse は答えの Message-Authenticator を、要求の Authenticator に戻して確かめる。
func validMessageAuthenticatorResponse(b []byte, reqAuth [16]byte, secret []byte) bool {
	cp := append([]byte(nil), b...)
	copy(cp[4:20], reqAuth[:])
	return validMessageAuthenticator(cp, secret)
}

// supplicant は EAP-TLS で認証する端末の役。答えの最後のパケットを返す。
func supplicant(t *testing.T, addr string, cert tls.Certificate, roots *x509.CertPool, maxVersion uint16) *radius.Packet {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(state []byte, eap eapPacket) *radius.Packet {
		req := radius.New(radius.CodeAccessRequest, secret)
		_ = rfc2865.UserName_SetString(req, "dev1")
		_ = rfc2869.EAPMessage_Set(req, eap.encode())
		if state != nil {
			_ = rfc2865.State_Set(req, state)
		}
		return exchange(t, conn, req)
	}
	resp := send(nil, eapPacket{Code: eapResponse, ID: 1, Type: eapTypeIdentity, Data: []byte("dev1")})
	pc := newPipeConn()
	tc := tls.Client(pc, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: serverName, MaxVersion: maxVersion})
	done := make(chan error, 1)
	var in []byte
	var pending []byte
	for i := 0; i < 50; i++ {
		if resp.Code != radius.CodeAccessChallenge {
			return resp
		}
		eap, err := parseEAP(rfc2869.EAPMessage_Get(resp))
		if err != nil || eap.Type != eapTypeTLS {
			t.Fatal(err, eap)
		}
		state := rfc2865.State_Get(resp)
		f, _ := parseTLSData(eap.Data)
		reply := func(data []byte) {
			resp = send(state, eapPacket{Code: eapResponse, ID: eap.ID, Type: eapTypeTLS, Data: data})
		}
		switch {
		case f.Flags&tlsFlagStart != 0:
			go func() { done <- tc.Handshake() }()
			<-pc.waiting // ClientHello を書いて、答えを待つ
			pending = pc.takeOut()
		case len(pending) > 0 && len(f.Data) == 0: // サーバーが断片を受け取った
		default:
			in = append(in, f.Data...)
			if f.Flags&tlsFlagMore != 0 {
				reply([]byte{0})
				continue
			}
			pc.feed <- in
			in = nil
			select {
			case <-pc.waiting:
			case err := <-done:
				if err != nil {
					return send(state, eapPacket{Code: eapResponse, ID: eap.ID, Type: eapTypeTLS, Data: []byte{0}})
				}
				if tc.ConnectionState().Version == tls.VersionTLS13 {
					// サーバーの 0x00 を読む。
					go func() {
						b := make([]byte, 1)
						_, err := tc.Read(b)
						done <- err
					}()
					select {
					case <-pc.waiting:
					case <-done:
					}
				}
			}
			pending = pc.takeOut()
		}
		if len(pending) == 0 {
			reply([]byte{0})
			continue
		}
		fr := tlsFragment{Data: pending}
		if len(pending) > maxFragment {
			fr = tlsFragment{Flags: tlsFlagLength | tlsFlagMore, Total: len(pending), Data: pending[:maxFragment]}
		}
		pending = pending[len(fr.Data):]
		reply(fr.encode())
	}
	t.Fatal("too many rounds")
	return nil
}

func TestEAPTLS(t *testing.T) {
	e := newEnv(t)
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Cert)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		resp := supplicant(t, e.addr, e.client, roots, v)
		if resp.Code != radius.CodeAccessAccept || rfc2865.UserName_GetString(resp) != "dev1" || len(resp.Attributes) < 4 {
			t.Fatalf("version %x: %v", v, resp.Code)
		}
	}
	// 取り消した証明書では入れない。
	if _, err := e.store.DeleteNetworkCerts(context.Background(), "dev1"); err != nil {
		t.Fatal(err)
	}
	if resp := supplicant(t, e.addr, e.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessReject {
		t.Fatal(resp.Code)
	}
}

func TestRequireCompliant(t *testing.T) {
	e := newEnv(t)
	e.srv.RequireCompliant = true
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Cert)
	if resp := supplicant(t, e.addr, e.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessReject {
		t.Fatal(resp.Code)
	}
	if err := e.store.PutCompliance(context.Background(), core.DeviceCompliance{DeviceID: "dev1", Compliant: true}); err != nil {
		t.Fatal(err)
	}
	if resp := supplicant(t, e.addr, e.client, roots, tls.VersionTLS13); resp.Code != radius.CodeAccessAccept {
		t.Fatal(resp.Code)
	}
}

func TestRejectsWithoutMessageAuthenticator(t *testing.T) {
	e := newEnv(t)
	conn, _ := net.Dial("udp", e.addr)
	defer conn.Close()
	req := radius.New(radius.CodeAccessRequest, secret)
	_ = rfc2869.EAPMessage_Set(req, eapPacket{Code: eapResponse, ID: 1, Type: eapTypeIdentity, Data: []byte("x")}.encode())
	b, _ := req.Encode()
	_, _ = conn.Write(b)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 100)); err == nil {
		t.Fatal("answered without Message-Authenticator")
	}
}
