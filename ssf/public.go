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
	// IPv4 を埋め込んだ IPv6（NAT64 の 64:ff9b::/96、6to4 の 2002::/16）は、中の IPv4 でも確かめる。
	if v4, ok := embeddedIPv4(a); ok {
		return PublicAddr(v4)
	}
	return true
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixTo4.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
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
	return &http.Client{Timeout: 30 * time.Second, Transport: PublicTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// PublicTransport は PublicClient の Transport。つなぐたびに（転送の先でも）実際のアドレスを確かめる。
func PublicTransport() *http.Transport {
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
	return tr
}

var publicClient = PublicClient()
