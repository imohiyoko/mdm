// Package radiusd は Wi-Fi のアクセスポイント（ルーター）からの認証を受ける RADIUS のサーバー。
// 端末は MDM が発行した証明書で EAP-TLS の認証をする（WPA2・WPA3 Enterprise）。
package radiusd

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // RADIUS の Message-Authenticator は HMAC-MD5 と決まっている（RFC 3579）
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/vendors/microsoft"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/pki"
)

// Client は RADIUS で問い合わせてくるアクセスポイント（ルーター）。
type Client struct {
	Name string
	// Prefix は UDP で問い合わせてくるアドレス。RadSec のルーターには無い（証明書で見分ける）。
	Prefix netip.Prefix
	// RadSecID と RadSecFingerprint は RadSec（RADIUS over TLS）のルーターの証明書の名前と指紋。
	RadSecID          string
	RadSecFingerprint string
	Secret            []byte
	// OrgIDs があれば、その組織の端末だけを入れる（組織ごとのルーター）。空ならどの組織の端末も入れる。
	OrgIDs []string

	from netip.Addr // 要求を送ってきたアドレス（client が埋める）
}

// Server は EAP-TLS の RADIUS のサーバー。
type Server struct {
	Store   core.Store
	Clock   core.Clock
	CA      *pki.CA // ネットワークの認証局（端末の証明書を確かめる）
	TLSCert tls.Certificate
	Clients []Client
	// RequireCompliant なら、準拠している端末だけを入れる。
	RequireCompliant bool
	// RadSecCA は RadSec のルーターの証明書を発行した認証局。無ければ RadSec を受けない。
	RadSecCA *pki.CA
	// Dynamic があれば、組織の管理者が登録したルーターも受ける。Refresh と 30 秒ごとに読み直す。
	Dynamic func(ctx context.Context) ([]Client, error)
	Logger  *slog.Logger

	dmu sync.RWMutex
	dyn []Client

	mu       sync.Mutex
	sessions map[string]*session
	replies  map[replyKey]cachedReply
}

type replyKey struct {
	addr string
	id   byte
	auth [16]byte
}

type cachedReply struct {
	b       []byte
	expires time.Time
}

const (
	sessionTTL   = time.Minute
	maxFragment  = 1000
	maxTLSRecord = 64 << 10
)

func (s *Server) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

func (s *Server) client(addr net.Addr) (Client, bool) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return Client{}, false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return Client{}, false
	}
	ip = ip.Unmap()
	// 範囲が重なるときは、いちばん狭い範囲のルーターにする（広い範囲の設定で組織の制限を外さないため）。
	best, found := Client{}, false
	s.dmu.RLock()
	all := append(slices.Clip(s.Clients), s.dyn...)
	s.dmu.RUnlock()
	for _, c := range all {
		if c.Prefix.Contains(ip) && (!found || c.Prefix.Bits() > best.Prefix.Bits()) {
			best, found = c, true
		}
	}
	best.from = ip
	return best, found
}

// Serve は conn で RADIUS の要求を受ける。ctx が終わると戻る。
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	if err := s.Refresh(ctx); err != nil {
		s.log().Error("radius: ルーターの一覧を読めない", "err", err)
	}
	go s.janitor(ctx)
	buf := make([]byte, radius.MaxPacketLength)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			if out := s.handle(ctx, addr, pkt); out != nil {
				_, _ = conn.WriteTo(out, addr)
			}
		}()
	}
}

// Refresh は組織の管理者が登録したルーターを読み直す。
func (s *Server) Refresh(ctx context.Context) error {
	if s.Dynamic == nil {
		return nil
	}
	cs, err := s.Dynamic(ctx)
	if err != nil {
		return err
	}
	s.dmu.Lock()
	s.dyn = cs
	s.dmu.Unlock()
	return nil
}

func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n%3 == 0 {
			if err := s.Refresh(ctx); err != nil {
				s.log().Error("radius: ルーターの一覧を読めない", "err", err)
			}
		}
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.sessions {
			if now.After(v.expires) {
				v.close()
				delete(s.sessions, k)
			}
		}
		for k, v := range s.replies {
			if now.After(v.expires) {
				delete(s.replies, k)
			}
		}
		s.mu.Unlock()
	}
}

// handle は 1 つの要求を処理し、答え（無ければ nil）を返す。
func (s *Server) handle(ctx context.Context, addr net.Addr, b []byte) []byte {
	c, ok := s.client(addr)
	if !ok {
		s.log().Warn("radius: 知らないところからの要求", "addr", addr.String())
		return nil
	}
	return s.handleFrom(ctx, c, addr.String(), b)
}

// handleFrom はルーター c からの要求を処理する。key は送り直しを見分けるための送り元。
func (s *Server) handleFrom(ctx context.Context, c Client, from string, b []byte) []byte {
	if len(b) < 20 {
		return nil
	}
	req, err := radius.Parse(b, c.Secret)
	if err != nil || req.Code != radius.CodeAccessRequest {
		return nil
	}
	// 同じ要求の送り直しには、同じ答えを返す（EAP の手順を進めない）。
	key := replyKey{addr: from, id: req.Identifier, auth: req.Authenticator}
	s.mu.Lock()
	if r, ok := s.replies[key]; ok {
		s.mu.Unlock()
		return r.b
	}
	s.mu.Unlock()
	// Message-Authenticator はいつも求める（RFC 3579。BlastRADIUS の対策も兼ねる）。
	if !validMessageAuthenticator(b, c.Secret) {
		s.log().Warn("radius: Message-Authenticator が無いか正しくない", "client", c.Name)
		return nil
	}
	resp := s.access(ctx, c, req)
	out, err := encodeWithMA(resp)
	if err != nil {
		s.log().Error("radius encode", "err", err)
		return nil
	}
	s.mu.Lock()
	if s.replies == nil {
		s.replies = map[replyKey]cachedReply{}
	}
	s.replies[key] = cachedReply{b: out, expires: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return out
}

func validMessageAuthenticator(b, secret []byte) bool {
	length := int(b[2])<<8 | int(b[3])
	if length > len(b) {
		return false
	}
	b = b[:length]
	// 属性をたどって Message-Authenticator（80）を探す。
	for i := 20; i+2 <= len(b); {
		l := int(b[i+1])
		if l < 2 || i+l > len(b) {
			return false
		}
		if b[i] == byte(rfc2869.MessageAuthenticator_Type) && l == 18 {
			got := append([]byte(nil), b[i+2:i+18]...)
			cp := append([]byte(nil), b...)
			clear(cp[i+2 : i+18])
			m := hmac.New(md5.New, secret)
			m.Write(cp)
			return hmac.Equal(got, m.Sum(nil))
		}
		i += l
	}
	return false
}

// encodeWithMA は答えに Message-Authenticator を付けて書く。HMAC は要求の Authenticator を入れた形で計算する。
func encodeWithMA(p *radius.Packet) ([]byte, error) {
	rfc2869.MessageAuthenticator_Del(p)
	if err := rfc2869.MessageAuthenticator_Set(p, make([]byte, 16)); err != nil {
		return nil, err
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	m := hmac.New(md5.New, p.Secret)
	m.Write(raw)
	if err := rfc2869.MessageAuthenticator_Set(p, m.Sum(nil)); err != nil {
		return nil, err
	}
	return p.Encode()
}

// --- EAP の手順

type session struct {
	mu       sync.Mutex
	state    string
	eapID    byte
	conn     *pipeConn
	tls      *tls.Conn
	started  bool
	done     chan error
	finished bool  // TLS の手順が終わった
	result   error // 手順の結果（finished のとき）
	pending  []byte
	inBuf    []byte
	expires  time.Time // s.mu の下で読み書きする
	identity string
	deviceID string
	client   Client // 手順を始めたルーター
}

func (ss *session) close() {
	if ss.conn != nil {
		_ = ss.conn.Close()
	}
}

func (s *Server) newSession() *session {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	ss := &session{state: base64.RawURLEncoding.EncodeToString(b), expires: time.Now().Add(sessionTTL)}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[string]*session{}
	}
	s.sessions[ss.state] = ss
	s.mu.Unlock()
	return ss
}

func (s *Server) takeSession(state string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[state]
	if ss != nil && time.Now().After(ss.expires) {
		ss.close()
		delete(s.sessions, state)
		return nil
	}
	return ss
}

func (s *Server) dropSession(ss *session) {
	s.mu.Lock()
	delete(s.sessions, ss.state)
	s.mu.Unlock()
	ss.close()
}

func reject(req *radius.Packet, id byte) *radius.Packet {
	resp := req.Response(radius.CodeAccessReject)
	_ = rfc2869.EAPMessage_Set(resp, eapPacket{Code: eapFailure, ID: id}.encode())
	return resp
}

func challenge(req *radius.Packet, ss *session, eap eapPacket) *radius.Packet {
	resp := req.Response(radius.CodeAccessChallenge)
	_ = rfc2869.EAPMessage_Set(resp, eap.encode())
	_ = rfc2865.State_SetString(resp, ss.state)
	return resp
}

func (s *Server) access(ctx context.Context, c Client, req *radius.Packet) *radius.Packet {
	raw, err := rfc2869.EAPMessage_Lookup(req)
	if err != nil {
		return req.Response(radius.CodeAccessReject) // EAP 以外（パスワードなど）は受けない
	}
	eap, err := parseEAP(raw)
	if err != nil || eap.Code != eapResponse {
		return reject(req, 0)
	}
	state := rfc2865.State_GetString(req)
	if state == "" {
		// 最初は EAP-Response/Identity。EAP-TLS を始める。
		if eap.Type != eapTypeIdentity {
			return reject(req, eap.ID)
		}
		ss := s.newSession()
		ss.client = c
		ss.identity = string(eap.Data)
		ss.eapID = eap.ID + 1
		return challenge(req, ss, eapPacket{Code: eapRequest, ID: ss.eapID, Type: eapTypeTLS, Data: []byte{tlsFlagStart}})
	}
	ss := s.takeSession(state)
	if ss == nil {
		return reject(req, eap.ID)
	}
	if ss.client.Name != c.Name || ss.client.from != c.from {
		// 別のルーター（同じ範囲の別のアドレスも）が始めた手順は続けない。
		return reject(req, eap.ID)
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if eap.ID != ss.eapID {
		return reject(req, eap.ID)
	}
	if eap.Type != eapTypeTLS { // Nak など：EAP-TLS を使えない端末
		s.log().Info("radius: 端末が EAP-TLS を使わなかった", "client", c.Name, "identity", ss.identity, "type", eap.Type)
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	frag, err := parseTLSData(eap.Data)
	if err != nil {
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	s.mu.Lock() // expires は janitor・takeSession が s.mu の下で読む
	ss.expires = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	next := ss.eapID + 1

	// 送りかけのものがあれば、端末の受け取り（空の EAP-TLS）を待って続きを送る。
	if len(ss.pending) > 0 {
		if len(frag.Data) != 0 {
			s.dropSession(ss)
			return reject(req, eap.ID)
		}
		return s.sendFragment(req, ss, next)
	}
	// 端末からの断片を集める。
	if len(ss.inBuf)+len(frag.Data) > maxTLSRecord {
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	ss.inBuf = append(ss.inBuf, frag.Data...)
	if frag.Flags&tlsFlagMore != 0 {
		ss.eapID = next
		return challenge(req, ss, eapPacket{Code: eapRequest, ID: next, Type: eapTypeTLS, Data: []byte{0}})
	}
	in := ss.inBuf
	ss.inBuf = nil

	if ss.finished {
		// TLS の手順のあとの、端末の最後の受け取り。
		if len(in) != 0 || ss.result != nil {
			s.dropSession(ss)
			return reject(req, eap.ID)
		}
		return s.accept(req, ss, eap.ID)
	}
	if len(in) == 0 {
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	out, err := s.step(ctx, ss, in)
	if err != nil {
		s.log().Info("radius: 認証できなかった", "client", c.Name, "identity", ss.identity, "device", ss.deviceID, "err", err)
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	if len(out) == 0 {
		if ss.finished {
			return s.accept(req, ss, eap.ID)
		}
		s.dropSession(ss)
		return reject(req, eap.ID)
	}
	ss.pending = out
	return s.sendFragment(req, ss, next)
}

func (s *Server) sendFragment(req *radius.Packet, ss *session, id byte) *radius.Packet {
	f := tlsFragment{}
	total := len(ss.pending)
	n := min(total, maxFragment)
	if n < total {
		f.Flags = tlsFlagLength | tlsFlagMore
		f.Total = total
	}
	f.Data = ss.pending[:n]
	ss.pending = ss.pending[n:]
	ss.eapID = id
	return challenge(req, ss, eapPacket{Code: eapRequest, ID: id, Type: eapTypeTLS, Data: f.encode()})
}

// step は端末からの TLS のデータを渡し、TLS が次に入力を待つか、手順が終わるまで進めて、送るものを返す。
func (s *Server) step(ctx context.Context, ss *session, in []byte) ([]byte, error) {
	if !ss.started {
		ss.started = true
		ss.conn = newPipeConn()
		ss.done = make(chan error, 1)
		cfg := s.tlsConfig(ss)
		ss.tls = tls.Server(ss.conn, cfg)
		go func() {
			hctx, cancel := context.WithTimeout(context.Background(), sessionTTL)
			defer cancel()
			err := ss.tls.HandshakeContext(hctx)
			if err == nil && ss.tls.ConnectionState().Version == tls.VersionTLS13 {
				// RFC 9190 2.5：手順が終わったことを 1 バイトの 0x00 で示す。
				_, err = ss.tls.Write([]byte{0})
			}
			ss.done <- err
		}()
		// TLS が最初の入力（ClientHello）を待つまで待つ。待っている知らせを先に受けておかないと、
		// 次の知らせと取り違える。
		select {
		case <-ss.conn.waiting:
		case err := <-ss.done:
			return nil, s.finish(ss, err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// ここでは TLS は入力を待っている（前の知らせは受けてある）。
	select {
	case ss.conn.feed <- in:
	case <-ss.conn.done:
		// 同時に期限切れで片付けられた（janitor・takeSession）。
		return nil, errClosed
	case err := <-ss.done:
		return nil, s.finish(ss, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-ss.conn.waiting:
		return ss.conn.takeOut(), nil
	case err := <-ss.done:
		if err := s.finish(ss, err); err != nil {
			return nil, err
		}
		return ss.conn.takeOut(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) finish(ss *session, err error) error {
	ss.finished, ss.result = true, err
	return err
}

func (s *Server) tlsConfig(ss *session) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	return &tls.Config{
		Certificates:           []tls.Certificate{s.TLSCert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		Time:                   s.Clock.Now,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			id, err := s.authorize(context.Background(), cs.PeerCertificates[0], ss.client)
			ss.deviceID = id
			return err
		},
	}
}

// authorize は端末の証明書が MDM の発行したもので、取り消されていないかを確かめる。
func (s *Server) authorize(ctx context.Context, cert *x509.Certificate, c Client) (string, error) {
	id := cert.Subject.CommonName
	nc, err := s.Store.GetNetworkCert(ctx, pki.Fingerprint(cert))
	if errors.Is(err, core.ErrNotFound) {
		return id, errors.New("certificate revoked or unknown")
	}
	if err != nil {
		return id, err
	}
	if nc.DeviceID != id {
		return id, errors.New("certificate does not match the device")
	}
	if len(c.OrgIDs) > 0 {
		d, err := s.Store.GetDevice(ctx, id)
		if err != nil {
			return id, err
		}
		if !slices.Contains(c.OrgIDs, d.OrgID) {
			return id, fmt.Errorf("device belongs to another organization (%s)", d.OrgID)
		}
	}
	if s.RequireCompliant {
		c, err := s.Store.GetCompliance(ctx, id)
		if err != nil || !c.Compliant {
			return id, fmt.Errorf("device is not compliant")
		}
	}
	return id, nil
}

// accept は認証を通し、Wi-Fi の暗号の鍵（MSK）をアクセスポイントに渡す。
func (s *Server) accept(req *radius.Packet, ss *session, id byte) *radius.Packet {
	defer s.dropSession(ss)
	cs := ss.tls.ConnectionState()
	var km []byte
	var err error
	if cs.Version == tls.VersionTLS13 {
		km, err = cs.ExportKeyingMaterial("EXPORTER_EAP_TLS_Key_Material", []byte{eapTypeTLS}, 128) // RFC 9190 2.3
	} else {
		km, err = cs.ExportKeyingMaterial("client EAP encryption", nil, 128) // RFC 5216 2.3
	}
	if err != nil {
		s.log().Warn("radius: 鍵を作れなかった（端末が Extended Master Secret を使っていない）", "device", ss.deviceID, "err", err)
		return reject(req, id)
	}
	resp := req.Response(radius.CodeAccessAccept)
	_ = rfc2869.EAPMessage_Set(resp, eapPacket{Code: eapSuccess, ID: id}.encode())
	if err := microsoft.MSMPPERecvKey_Set(resp, km[0:32]); err != nil {
		return reject(req, id)
	}
	if err := microsoft.MSMPPESendKey_Set(resp, km[32:64]); err != nil {
		return reject(req, id)
	}
	_ = rfc2865.UserName_SetString(resp, ss.deviceID)
	s.log().Info("radius: 端末を入れた", "device", ss.deviceID, "tls", tls.VersionName(cs.Version))
	return resp
}
