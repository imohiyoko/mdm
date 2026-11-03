package resolver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/resolver"
)

// fakeUpstream は A に 192.0.2.1 で答える。
type fakeUpstream struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (u *fakeUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	u.mu.Lock()
	u.calls++
	fail := u.fail
	u.mu.Unlock()
	if fail {
		return nil, io.ErrUnexpectedEOF
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})
	return b.Finish()
}

type env struct {
	store    core.Store
	clock    *testkit.Clock
	up       *fakeUpstream
	res      *resolver.Resolver
	qlog     *resolver.QueryLogger
	token    string
	deviceID string
}

func newEnv(t *testing.T, logQueries bool) *env {
	t.Helper()
	ctx := context.Background()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	if err := store.CreatePolicy(ctx, core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist, Block: []string{"blocked.example"}, LogQueries: logQueries}); err != nil {
		t.Fatal(err)
	}
	token, hash := core.NewFilterToken()
	if err := store.CreateDevice(ctx, core.Device{ID: "dev1", Name: "たろうの iPhone", Platform: core.PlatformIOS, FilterTokenHash: hash}); err != nil {
		t.Fatal(err)
	}
	engine := &filter.Engine{Store: store, Clock: clock}
	up := &fakeUpstream{}
	qlog := &resolver.QueryLogger{Store: store, Clock: clock}
	return &env{store, clock, up, &resolver.Resolver{Engine: engine, Upstream: up, Log: qlog}, qlog, token, "dev1"}
}

func query(t *testing.T, name string, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if edns {
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func parse(t *testing.T, msg []byte) (dnsmessage.Message, bool) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatal(err)
	}
	blocked := false
	for _, a := range m.Additionals {
		if opt, ok := a.Body.(*dnsmessage.OPTResource); ok {
			for _, o := range opt.Options {
				if o.Code == 15 && bytes.Equal(o.Data, []byte{0, 15}) {
					blocked = true
				}
			}
		}
	}
	return m, blocked
}

func TestHandle(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	resp, err := e.res.Handle(ctx, e.token, query(t, "www.blocked.example.", true))
	if err != nil {
		t.Fatal(err)
	}
	m, ede := parse(t, resp)
	if m.RCode != dnsmessage.RCodeNameError || m.ID != 0xbeef || !m.Response || !ede || e.up.calls != 0 {
		t.Fatalf("止める: %+v ede=%v calls=%d", m.Header, ede, e.up.calls)
	}

	resp, err = e.res.Handle(ctx, e.token, query(t, "ok.example.", false))
	if err != nil {
		t.Fatal(err)
	}
	m, _ = parse(t, resp)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || e.up.calls != 1 {
		t.Fatalf("通す: %+v", m)
	}

	e.up.fail = true
	resp, _ = e.res.Handle(ctx, e.token, query(t, "ok.example.", false))
	if m, _ = parse(t, resp); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("上流の失敗は SERVFAIL: %v", m.RCode)
	}

	if _, err := e.res.Handle(ctx, strings.Repeat("a", 32), query(t, "ok.example.", false)); err != resolver.ErrUnknownDevice {
		t.Fatalf("知らない端末: %v", err)
	}
	if _, err := e.res.Handle(ctx, e.token, []byte{1, 2}); err == nil {
		t.Fatal("壊れたメッセージ")
	}

	// 通したものはポリシーで残さないと決めているので、止めたものだけ残る。
	if err := e.qlog.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	logs, _ := e.store.ListQueryLogs(ctx, e.deviceID, time.Time{}, 10)
	if len(logs) != 1 || logs[0].Name != "www.blocked.example" || logs[0].Action != core.ActionBlock || logs[0].Type != "A" {
		t.Fatalf("記録: %+v", logs)
	}
	d, _ := e.store.GetDevice(ctx, e.deviceID)
	if d.LastSeenAt.IsZero() {
		t.Fatal("最後の通信の時刻")
	}
}

func TestDoH(t *testing.T) {
	e := newEnv(t, true)
	h := (&resolver.PublicHandler{Resolver: e.res, DoHBaseURL: "https://dns.example"}).Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	msg := query(t, "ok.example.", false)
	resp, err := http.Post(srv.URL+"/dns-query/"+e.token, "application/dns-message", bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
	if m, _ := parse(t, body); len(m.Answers) != 1 {
		t.Fatalf("POST の答え: %+v", m)
	}

	resp, err = http.Get(srv.URL + "/dns-query/" + e.token + "?dns=" + base64.RawURLEncoding.EncodeToString(query(t, "blocked.example.", false)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if m, _ := parse(t, body); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("GET: %v", m.RCode)
	}

	for _, c := range []struct {
		method, path, ct string
		want             int
	}{
		{"POST", "/dns-query/" + strings.Repeat("a", 32), "application/dns-message", 404},
		{"POST", "/dns-query/" + e.token, "text/plain", 415},
		{"PUT", "/dns-query/" + e.token, "application/dns-message", 405},
		{"GET", "/dns-query/", "", 404},
	} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, bytes.NewReader(msg))
		if c.ct != "" {
			req.Header.Set("Content-Type", c.ct)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}

	// iPhone・Mac の設定のプロファイル。
	resp, err = http.Get(srv.URL + "/setup/apple/" + e.token + ".mobileconfig")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("profile: %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("https://dns.example/dns-query/"+e.token)) || !bytes.Contains(body, []byte("たろうの iPhone")) {
		t.Fatalf("profile の中身: %s", body)
	}
	if err := xml.Unmarshal(body, new(struct{ XMLName xml.Name })); err != nil {
		t.Fatalf("XML として読めない: %v", err)
	}
	resp, _ = http.Get(srv.URL + "/setup/apple/" + strings.Repeat("a", 32) + ".mobileconfig")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("知らない端末の profile: %d", resp.StatusCode)
	}
}

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestDoT(t *testing.T) {
	e := newEnv(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t, "*.dns.example")
	s := &resolver.DoTServer{Resolver: e.res, Domain: "dns.example", TLS: &tls.Config{Certificates: []tls.Certificate{cert}}}
	done := make(chan error)
	go func() { done <- s.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	dial := func(sni string) *tls.Conn {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := dial(strings.ToUpper(e.token) + ".dns.example")
	defer c.Close()
	for _, name := range []string{"ok.example.", "blocked.example."} {
		if err := resolver.WriteFramed(c, query(t, name, false)); err != nil {
			t.Fatal(err)
		}
		resp, err := resolver.ReadFramed(c)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := parse(t, resp)
		if name == "ok.example." && len(m.Answers) != 1 || name == "blocked.example." && m.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s: %+v", name, m)
		}
	}

	// 知らない秘密の接続は閉じる。
	bad := dial(strings.Repeat("a", 32) + ".dns.example")
	defer bad.Close()
	_ = resolver.WriteFramed(bad, query(t, "ok.example.", false))
	_ = bad.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := resolver.ReadFramed(bad); err == nil {
		t.Fatal("知らない端末に答えた")
	}
}

func TestTokenFromServerName(t *testing.T) {
	for sni, want := range map[string]string{
		"abc.dns.example":   "abc",
		"ABC.DNS.EXAMPLE.":  "abc",
		"a.b.dns.example":   "",
		"dns.example":       "",
		"abc.other.example": "",
		"abc.xdns.example":  "",
	} {
		got, ok := resolver.TokenFromServerName(sni, "dns.example")
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v", sni, got, ok)
		}
	}
}
