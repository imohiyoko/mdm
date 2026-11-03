package adminapi_test

import (
	"encoding/base64"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/network"
	"github.com/imohiyoko/mdm/pki"
)

func TestNetworkCertAPI(t *testing.T) {
	ca, err := pki.NewNetworkCA("net", "radius.home.example")
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := newServer(t, func(s *adminapi.Server) {
		s.Network = &network.Service{Store: s.Store, Clock: s.Clock, CA: ca, ServerName: "radius.home.example"}
	})
	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "TV", "platform": "other"}, &dev)
	id := dev.Device["id"].(string)
	var out map[string]any
	if code := c.do("POST", "/v1/devices/"+id+"/network-cert", map[string]any{}, &out); code != 200 || out["server_name"] != "radius.home.example" || out["identity"] != id {
		t.Fatal(code, out)
	}
	p12, _ := base64.StdEncoding.DecodeString(out["pkcs12"].(string))
	_, cert, chain, err := pkcs12.DecodeChain(p12, out["password"].(string))
	if err != nil || cert.Subject.CommonName != id || len(chain) != 1 || pki.Fingerprint(cert) != out["fingerprint"] {
		t.Fatal(err)
	}
	// もう一度発行すると、前の証明書は取り消される。keep_previous なら残る。
	c.do("POST", "/v1/devices/"+id+"/network-cert", map[string]any{}, nil)
	c.do("POST", "/v1/devices/"+id+"/network-cert", map[string]any{"keep_previous": true}, nil)
	var list struct{ Certs []map[string]any }
	if c.do("GET", "/v1/devices/"+id+"/network-cert", nil, &list); len(list.Certs) != 2 {
		t.Fatal(list)
	}
	if code := c.do("DELETE", "/v1/devices/"+id+"/network-cert", nil, nil); code != 204 {
		t.Fatal(code)
	}
	if c.do("GET", "/v1/devices/"+id+"/network-cert", nil, &list); len(list.Certs) != 0 {
		t.Fatal(list)
	}
}

func TestNetworkCertNotConfigured(t *testing.T) {
	c, _, _ := newServer(t)
	var dev struct{ Device map[string]any }
	c.do("POST", "/v1/devices", map[string]any{"org_id": testkit.OrgID, "name": "TV", "platform": "other"}, &dev)
	if code := c.do("POST", "/v1/devices/"+dev.Device["id"].(string)+"/network-cert", map[string]any{}, nil); code != 501 {
		t.Fatal(code)
	}
}
