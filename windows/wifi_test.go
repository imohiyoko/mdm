package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/network"
	"github.com/imohiyoko/mdm/pki"
)

type sent struct{ verb, uri, data string }

// session は端末として 1 回やり取りし、送られた命令にすべて答える。codes が空でない値を返したら、その答えを返す。
// 答えたあとに送られた命令にも答え続け、送られた命令をすべて返す。
func (e *env) session(t *testing.T, c *http.Client, codes func(verb, uri string) string) []sent {
	t.Helper()
	var all []sent
	_, out := e.manage(t, c, msg("1", start))
	for i := 2; i < 10; i++ {
		cmds := commands(out)
		if len(cmds) == 0 {
			break
		}
		var b bytes.Buffer
		for n, x := range cmds {
			uri := x.Items[0].Target.LocURI
			all = append(all, sent{x.XMLName.Local, uri, x.Items[0].Data.text()})
			code := "200"
			if codes != nil {
				if v := codes(x.XMLName.Local, uri); v != "" {
					code = v
				}
			}
			fmt.Fprintf(&b, `<Status><CmdID>%d</CmdID><MsgRef>1</MsgRef><CmdRef>%s</CmdRef><Cmd>%s</Cmd><Data>%s</Data></Status>`, 10+n, x.CmdID, x.XMLName.Local, code)
		}
		_, out = e.manage(t, c, msg(fmt.Sprint(i), b.String()))
	}
	return all
}

func wifiOnly(ss []sent) []sent {
	var out []sent
	for _, s := range ss {
		if strings.Contains(s.uri, "/WiFi/") || strings.Contains(s.uri, "/ClientCertificateInstall/") || strings.Contains(s.uri, "/RootCATrustedCertificates/") {
			out = append(out, s)
		}
	}
	return out
}

func find(ss []sent, verb, suffix string) *sent {
	for i := range ss {
		if ss[i].verb == verb && strings.HasSuffix(ss[i].uri, suffix) {
			return &ss[i]
		}
	}
	return nil
}

func newWiFiEnv(t *testing.T) *env {
	e := newEnv(t)
	ca, err := pki.NewNetworkCA("net CA", "radius.test")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Network = &network.Service{Store: e.store, Clock: e.clock, CA: ca, ServerName: "radius.test"}
	return e
}

func (e *env) setWiFi(t *testing.T, nets []core.WiFiNetwork) {
	t.Helper()
	ctx := context.Background()
	pol, _ := e.store.GetPolicy(ctx, filter.DefaultPolicyID)
	pol.WiFi = nets
	if err := e.store.UpdatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
}

func (e *env) certs(t *testing.T) []string {
	t.Helper()
	cs, _ := e.store.ListNetworkCerts(context.Background(), e.dev.ID)
	var out []string
	for _, c := range cs {
		out = append(out, c.Fingerprint)
	}
	return out
}

// checkPFX は配られた証明書を読み、指紋を返す。
func checkPFX(t *testing.T, e *env, ss []sent) string {
	t.Helper()
	pw, blob := find(ss, "Add", "/PFXCertPassword"), find(ss, "Add", pfxBlobLeaf)
	if pw == nil || blob == nil || find(ss, "Add", "/KeyLocation") == nil {
		t.Fatal(ss)
	}
	p12, err := base64.StdEncoding.DecodeString(blob.data)
	if err != nil {
		t.Fatal(err)
	}
	_, cert, _, err := pkcs12.DecodeChain(p12, pw.data)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := e.svc.Network.CA.Verify(cert, e.clock.Now()); err != nil || id != e.dev.ID {
		t.Fatal(id, err)
	}
	fp := pki.Fingerprint(cert)
	if !strings.HasPrefix(blob.uri, uriPFX+pfxID(fp)+"/") {
		t.Fatal(blob.uri)
	}
	return fp
}

func TestWiFi(t *testing.T) {
	e := newWiFiEnv(t)
	ctx := context.Background()
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home net"}})
	c := e.enroll(t)
	ws := wifiOnly(e.session(t, c, nil))
	ca := e.svc.Network.CA.Cert
	root := find(ws, "Add", "/EncodedCertificate")
	if root == nil || root.uri != uriRootCA+thumbprint(ca.Raw)+"/EncodedCertificate" || root.data != base64.StdEncoding.EncodeToString(ca.Raw) {
		t.Fatal(root)
	}
	fp := checkPFX(t, e, ws)
	wlan := find(ws, "Add", "/WlanXml")
	if wlan == nil || wlan.uri != uriWiFi+"home%20net/WlanXml" {
		t.Fatal(ws)
	}
	var prof struct {
		Name   string `xml:"name"`
		Hex    string `xml:"SSIDConfig>SSID>hex"`
		Auth   string `xml:"MSM>security>authEncryption>authentication"`
		OneX   bool   `xml:"MSM>security>authEncryption>useOneX"`
		Mode   string `xml:"MSM>security>OneX>authMode"`
		Type   int    `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>EapMethod>Type"`
		Server string `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>Config>Eap>EapType>ServerValidation>ServerNames"`
		Root   string `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>Config>Eap>EapType>ServerValidation>TrustedRootCA"`
	}
	if err := xml.Unmarshal([]byte(wlan.data), &prof); err != nil {
		t.Fatal(err, wlan.data)
	}
	if prof.Name != "home net" || prof.Hex != "686F6D65206E6574" || prof.Auth != "WPA2" || !prof.OneX || prof.Mode != "machine" || prof.Type != 13 ||
		prof.Server != "radius.test" || prof.Root != spacedThumbprint(ca.Raw) {
		t.Fatalf("%+v", prof)
	}
	if got := e.certs(t); len(got) != 1 || got[0] != fp {
		t.Fatal(got)
	}
	// 鍵の合言葉と PFX は残さない。
	cmds, _ := e.store.ListCommands(ctx, e.dev.ID, 200)
	for _, x := range cmds {
		if x.Purpose == purposeWiFi && x.Data != "" {
			t.Fatalf("kept: %+v", x)
		}
	}
	if m, _ := e.store.GetManaged(ctx, e.dev.ID); !m.PolicyCompliant {
		t.Fatalf("%+v", m)
	}

	// 変わらなければ配り直さない。
	e.clock.Advance(15 * time.Minute)
	if ws := wifiOnly(e.session(t, c, nil)); len(ws) != 0 {
		t.Fatal(ws)
	}

	// 期限が近づいたら新しい証明書を配り、入ったら前の証明書を消して取り消す。設定は置き換える。
	e.clock.Advance(2*365*24*time.Hour - 20*24*time.Hour)
	ws = wifiOnly(e.session(t, c, nil))
	fp2 := checkPFX(t, e, ws)
	if find(ws, "Replace", "/WlanXml") == nil || find(ws, "Delete", uriPFX+pfxID(fp)) == nil {
		t.Fatal(ws)
	}
	if got := e.certs(t); len(got) != 1 || got[0] != fp2 {
		t.Fatal(got)
	}

	// 新しい証明書が入らなければ、前の証明書は残す。
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home net"}, {SSID: "office", Hidden: true}})
	e.clock.Advance(time.Hour)
	ws = wifiOnly(e.session(t, c, func(verb, uri string) string {
		if strings.HasSuffix(uri, pfxBlobLeaf) {
			return "500"
		}
		return ""
	}))
	if find(ws, "Add", pfxBlobLeaf) == nil || find(ws, "Delete", uriPFX+pfxID(fp2)) != nil {
		t.Fatal(ws)
	}
	if m := e.mustManaged(t); m.PolicyCompliant || len(m.Problems) == 0 {
		t.Fatalf("%+v", m)
	}
	if got := e.certs(t); len(got) != 2 {
		t.Fatal(got)
	}

	// 無くすと、設定と証明書を消して取り消す。
	last := e.mustManaged(t).WiFiCert
	e.setWiFi(t, nil)
	e.clock.Advance(time.Hour)
	ws = wifiOnly(e.session(t, c, nil))
	if find(ws, "Delete", "/WiFi/Profile/home%20net") == nil || find(ws, "Delete", "/WiFi/Profile/office") == nil || find(ws, "Delete", uriPFX+pfxID(last)) == nil {
		t.Fatal(ws)
	}
	if got := e.certs(t); len(got) != 0 {
		t.Fatal(got)
	}
}

func (e *env) mustManaged(t *testing.T) core.Managed {
	t.Helper()
	m, err := e.store.GetManaged(context.Background(), e.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// もうある Wi-Fi の設定（418）は置き換える。
func TestWiFiAlreadyExists(t *testing.T) {
	e := newWiFiEnv(t)
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home"}})
	c := e.enroll(t)
	ws := wifiOnly(e.session(t, c, func(verb, uri string) string {
		if verb == "Add" && uri == uriWiFi+"home/WlanXml" {
			return "418"
		}
		return ""
	}))
	add, rep := find(ws, "Add", "/WlanXml"), find(ws, "Replace", "/WlanXml")
	if add == nil || rep == nil || rep.data != add.data {
		t.Fatal(ws)
	}
	if m := e.mustManaged(t); !m.PolicyCompliant {
		t.Fatalf("%+v", m)
	}
}
