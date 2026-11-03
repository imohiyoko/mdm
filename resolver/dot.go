package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// DoTServer は端末からの DNS over TLS（RFC 7858）を受ける。
// 端末は TLS のホスト名（SNI）の先頭のラベルで見分ける：{label}.dns.example.com。
// Android の「プライベート DNS」はホスト名しか設定できないため、この形を使う。
// SNI は暗号化されずに流れるので、ラベルは DoH の秘密とは別の値にする（ADR 0002）。
type DoTServer struct {
	Resolver *Resolver
	// Domain は秘密の後ろに付くドメイン（"dns.example.com"）。
	Domain string
	TLS    *tls.Config
	// IdleTimeout は問い合わせの無い接続を閉じるまでの時間。
	IdleTimeout time.Duration
	// MaxConns は同時の接続の上限。
	MaxConns int
	Logger   *slog.Logger

	wg sync.WaitGroup
}

// LabelFromServerName は SNI から端末のラベルを取り出す。
func LabelFromServerName(serverName, domain string) (string, bool) {
	serverName = strings.ToLower(strings.TrimSuffix(serverName, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	token, ok := strings.CutSuffix(serverName, "."+domain)
	if !ok || token == "" || strings.Contains(token, ".") {
		return "", false
	}
	return token, true
}

// Serve は ln で受ける。ctx が終わると閉じる。
func (s *DoTServer) Serve(ctx context.Context, ln net.Listener) error {
	idle := s.IdleTimeout
	if idle == 0 {
		idle = 30 * time.Second
	}
	maxConns := s.MaxConns
	if maxConns == 0 {
		maxConns = 1000
	}
	sem := make(chan struct{}, maxConns)
	tln := tls.NewListener(ln, s.TLS)
	go func() {
		<-ctx.Done()
		tln.Close()
	}()
	for {
		conn, err := tln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-sem }()
			s.serveConn(ctx, conn.(*tls.Conn), idle)
		}()
	}
}

func (s *DoTServer) serveConn(ctx context.Context, conn *tls.Conn, idle time.Duration) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	label, ok := LabelFromServerName(conn.ConnectionState().ServerName, s.Domain)
	if !ok {
		return
	}
	for {
		_ = conn.SetDeadline(time.Now().Add(idle))
		msg, err := ReadFramed(conn)
		if err != nil {
			return
		}
		resp, err := s.Resolver.HandleDoT(ctx, label, msg)
		if err != nil {
			return // 知らない端末・壊れたメッセージは接続を閉じる
		}
		if err := WriteFramed(conn, resp); err != nil {
			return
		}
	}
}
