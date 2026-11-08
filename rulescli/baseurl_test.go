package rulescli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckBaseURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://mdm.example:8093": true, "http://127.0.0.1:8093": true, "http://localhost:8093": true, "http://[::1]:8093": true,
		"http://mdm.example:8093": false, "ftp://mdm.example": false, "https://u:p@mdm.example": false, "": false, "mdm.example": false,
	} {
		if err := checkBaseURL(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// https から http への転送には付いて行かない（鍵を平文で送らない）。
func TestRedirectToPlainHTTPRefused(t *testing.T) {
	// 手元の http は許すので、遠くの http を名乗る転送先で確かめる（つなぐ前に止まるので名前は引かない）。
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://mdm.example"+r.URL.Path, http.StatusFound)
	}))
	defer tls.Close()
	c := &Client{BaseURL: tls.URL, Token: "secret", HTTP: tls.Client()}
	err := c.do(context.Background(), http.MethodGet, "/v1/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "転送の先") {
		t.Fatalf("err = %v", err)
	}
}
