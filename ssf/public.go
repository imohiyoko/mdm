package ssf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// 組織の管理者が登録した受け手には、MDM のサーバーの内側（ループバック・社内のアドレス・クラウドのメタデータなど）へ
// 送らせない（SSRF の対策）。名前を引いたあとの、実際につなぐアドレスで確かめる。

var errNotPublic = errors.New("ssf: 受け手のアドレスがインターネットのものではない")

// PublicAddr はインターネットのアドレスか。
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF
	netip.MustParsePrefix("198.18.0.0/15"),  // 試験
	netip.MustParsePrefix("0.0.0.0/8"),      // この網
	netip.MustParsePrefix("64:ff9b:1::/48"), // ローカルの変換
	netip.MustParsePrefix("2001:db8::/32"),  // 文書用
	netip.MustParsePrefix("fec0::/10"),      // 古いサイトローカル
}

func publicControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !PublicAddr(ap.Addr()) {
		return errNotPublic
	}
	return nil
}

// PublicClient はインターネットのアドレスにだけつなぐ HTTP のクライアントを作る。プロキシは使わない（プロキシの先を確かめられないため）。
func PublicClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: publicControl}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     time.Minute,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var publicClient = PublicClient()
