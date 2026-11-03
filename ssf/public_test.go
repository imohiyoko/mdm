package ssf

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPublicAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.0.1": false, "172.16.0.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false, "::ffff:127.0.0.1": false,
		"224.0.0.1": false, "2001:db8::1": false,
	} {
		if got := PublicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
}

// 組織の管理者が登録した受け手は、内側のアドレスにつながない。
func TestPublicClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer srv.Close()
	if _, err := PublicClient().Get(srv.URL); err == nil {
		t.Fatal("connected to loopback")
	}
}
