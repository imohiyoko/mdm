package radiusd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"layeh.com/radius"

	"github.com/imohiyoko/mdm/pki"
)

// RadSec（RADIUS over TLS、RFC 6614）。ルーターは TCP の TLS でつなぎ、MDM が発行したクライアント証明書で自分を示す。
// アドレスで見分けないので、ルーターのアドレスが変わっても（家庭の回線など）使える。共有の秘密は RFC のとおり "radsec"。
//
// 端末の EAP-TLS とは別の TLS（ルーターと MDM のあいだ）。中を流れる RADIUS の扱いは UDP と同じ。

// RadSecSecret は RadSec の共有の秘密（RFC 6614 2.3）。
var RadSecSecret = []byte("radsec")

const (
	radsecIdle     = 10 * time.Minute
	maxRadSecConns = 1000
	// maxRadSecConnsPerIP は 1 つの接続元からの同時の接続の上限。握手をしないまま枠を占める接続から、
	// ほかのルーターを守る。同じアドレスの裏に多くのルーターがあっても足りる数にする。
	maxRadSecConnsPerIP = 64
	radsecHandshake     = 10 * time.Second
)

// RadSecTLS は RadSec の待ち受けの TLS の設定。ルーターの証明書は ca（ルーター用の認証局）で確かめる。
func (s *Server) RadSecTLS(ca *pki.CA) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{s.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
}

// radsecClient は証明書で RadSec のルーターを見分ける。消されたルーター・作り直した証明書は見つからない。
func (s *Server) radsecClient(cert *x509.Certificate, from netip.Addr) (Client, bool) {
	if s.RadSecCA == nil {
		return Client{}, false
	}
	id, err := s.RadSecCA.Verify(cert, s.Clock.Now())
	if err != nil {
		return Client{}, false
	}
	fp := pki.Fingerprint(cert)
	s.dmu.RLock()
	defer s.dmu.RUnlock()
	for _, c := range s.dyn {
		if c.RadSecID != "" && c.RadSecID == id && c.RadSecFingerprint == fp {
			c.Secret, c.from = RadSecSecret, from
			return c, true
		}
	}
	return Client{}, false
}

// ServeRadSec は ln（TLS の待ち受け）で RadSec の接続を受ける。ctx が終わると戻る。
func (s *Server) ServeRadSec(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	sem := make(chan struct{}, maxRadSecConns)
	var mu sync.Mutex
	perIP := map[netip.Addr]int{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ip := remoteIP(conn)
		mu.Lock()
		if perIP[ip] >= maxRadSecConnsPerIP {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		perIP[ip]++
		mu.Unlock()
		go func() {
			defer func() {
				mu.Lock()
				if perIP[ip]--; perIP[ip] <= 0 {
					delete(perIP, ip)
				}
				mu.Unlock()
				<-sem
			}()
			defer conn.Close()
			s.serveRadSecConn(ctx, conn)
		}()
	}
}

func remoteIP(conn net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (s *Server) serveRadSecConn(ctx context.Context, conn net.Conn) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	_ = tc.SetDeadline(time.Now().Add(radsecHandshake))
	if err := tc.HandshakeContext(ctx); err != nil {
		s.log().Info("radsec: TLS の握手に失敗", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	from := remoteIP(conn)
	key := "radsec:" + conn.RemoteAddr().String()
	hdr := make([]byte, 4)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(radsecIdle))
		if _, err := io.ReadFull(tc, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < 20 || n > radius.MaxPacketLength {
			return // 区切りが壊れている。読み続けられないので切る
		}
		b := make([]byte, n)
		copy(b, hdr)
		if _, err := io.ReadFull(tc, b[4:]); err != nil {
			return
		}
		// ルーターが消されていないか、要求ごとに確かめる。
		c, ok := s.radsecClient(certs[0], from)
		if !ok {
			s.log().Warn("radsec: 知らないルーターの証明書", "remote", conn.RemoteAddr().String(), "subject", certs[0].Subject.CommonName)
			return
		}
		out := s.handleFrom(ctx, c, key, b)
		if out == nil {
			continue
		}
		_ = tc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := tc.Write(out); err != nil {
			return
		}
	}
}
