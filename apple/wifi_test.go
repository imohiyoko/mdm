package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"slices"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/network"
	"github.com/imohiyoko/mdm/pki"
)

// drain は端末として命令をすべて受け取り、Acknowledged で答える。受け取った命令を返す。
func (e *env) drain(t *testing.T, c *http.Client) []map[string]any {
	t.Helper()
	var got []map[string]any
	_, cmd := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	for i := 0; i < 20 && cmd != nil; i++ {
		got = append(got, cmd)
		_, cmd = e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Acknowledged", "CommandUUID": cmd["CommandUUID"]})
	}
	return got
}

func isWiFi(cmd map[string]any) bool {
	c := cmd["Command"].(map[string]any)
	if c["RequestType"] == "RemoveProfile" {
		return c["Identifier"] == wifiIdentifier
	}
	p, _ := c["Payload"].([]byte)
	return bytes.Contains(p, []byte(wifiIdentifier))
}

func wifiCommands(cmds []map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range cmds {
		if isWiFi(c) {
			out = append(out, c)
		}
	}
	return out
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

// checkWiFiProfile は Wi-Fi のプロファイルの中身を確かめ、端末の証明書を返す。
func checkWiFiProfile(t *testing.T, e *env, cmd map[string]any, ssids ...string) *x509.Certificate {
	t.Helper()
	prof := installed(t, cmd)
	if prof["PayloadIdentifier"] != wifiIdentifier {
		t.Fatal(prof)
	}
	ps := prof["PayloadContent"].([]any)
	root, id := ps[0].(map[string]any), ps[1].(map[string]any)
	if root["PayloadType"] != "com.apple.security.root" || !bytes.Equal(root["PayloadContent"].([]byte), e.svc.Network.CA.Cert.Raw) {
		t.Fatal(root)
	}
	_, cert, _, err := pkcs12.DecodeChain(id["PayloadContent"].([]byte), id["Password"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if dev, err := e.svc.Network.CA.Verify(cert, e.clock.Now()); err != nil || dev != e.dev.ID {
		t.Fatal(dev, err)
	}
	if len(ps) != 2+len(ssids) {
		t.Fatal(len(ps))
	}
	for i, ssid := range ssids {
		w := ps[2+i].(map[string]any)
		eap := w["EAPClientConfiguration"].(map[string]any)
		if w["PayloadType"] != "com.apple.wifi.managed" || w["SSID_STR"] != ssid || w["PayloadCertificateUUID"] != id["PayloadUUID"] ||
			eap["AcceptEAPTypes"].([]any)[0] != uint64(13) || eap["TLSTrustedServerNames"].([]any)[0] != "radius.test" ||
			eap["PayloadCertificateAnchorUUID"].([]any)[0] != root["PayloadUUID"] || eap["UserName"] != e.dev.ID {
			t.Fatalf("%#v", w)
		}
	}
	return cert
}

func certs(t *testing.T, e *env) []string {
	t.Helper()
	cs, err := e.store.ListNetworkCerts(context.Background(), e.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, c := range cs {
		out = append(out, c.Fingerprint)
	}
	return out
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

func TestWiFi(t *testing.T) {
	e := newWiFiEnv(t)
	ctx := context.Background()
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home"}})
	c := e.enroll(t)
	e.checkIn(t, c)
	ws := wifiCommands(e.drain(t, c))
	if len(ws) != 1 {
		t.Fatal(len(ws))
	}
	cert := checkWiFiProfile(t, e, ws[0], "home")
	if got := certs(t, e); len(got) != 1 || got[0] != pki.Fingerprint(cert) {
		t.Fatal(got)
	}
	// 鍵は答えを受けたら残さない。
	cmds, _ := e.store.ListCommands(ctx, e.dev.ID, 100)
	for _, x := range cmds {
		if x.Purpose == purposeWiFi && x.Data != "" {
			t.Fatalf("key kept: %+v", x)
		}
	}
	if m, _ := e.store.GetManaged(ctx, e.dev.ID); !m.PolicyCompliant {
		t.Fatalf("%+v", m)
	}

	// 変わらなければ配り直さない。
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	if ws := wifiCommands(e.drain(t, c)); len(ws) != 0 {
		t.Fatal(len(ws))
	}

	// 期限が近づいたら新しい証明書を配る。前の証明書は、端末が新しいものを受け取るまで使える。
	e.clock.Advance(2*365*24*time.Hour - 20*24*time.Hour)
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := certs(t, e); len(got) != 2 {
		t.Fatal(got)
	}
	ws = wifiCommands(e.drain(t, c))
	if len(ws) != 1 {
		t.Fatal(len(ws))
	}
	cert2 := checkWiFiProfile(t, e, ws[0], "home")
	if got := certs(t, e); len(got) != 1 || got[0] != pki.Fingerprint(cert2) {
		t.Fatal(got)
	}

	// 管理の API で取り消したら、設定が変わるまで配り直さない。
	if _, err := e.store.DeleteNetworkCerts(ctx, e.dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	if ws := wifiCommands(e.drain(t, c)); len(ws) != 0 {
		t.Fatal(len(ws))
	}

	// ネットワークを足すと配り直す。
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home"}, {SSID: "office", Hidden: true}})
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	ws = wifiCommands(e.drain(t, c))
	if len(ws) != 1 {
		t.Fatal(len(ws))
	}
	checkWiFiProfile(t, e, ws[0], "home", "office")

	// 無くすと、プロファイルを消して証明書を取り消す。
	e.setWiFi(t, nil)
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	ws = wifiCommands(e.drain(t, c))
	if len(ws) != 1 || requestType(ws[0]) != "RemoveProfile" {
		t.Fatal(ws)
	}
	if got := certs(t, e); len(got) != 0 {
		t.Fatal(got)
	}
}

// 新しい証明書を受け取る前に失敗したら、鍵を残さず、前の証明書も残す。
func TestWiFiFailureKeepsPrevious(t *testing.T) {
	e := newWiFiEnv(t)
	ctx := context.Background()
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home"}})
	c := e.enroll(t)
	e.checkIn(t, c)
	e.drain(t, c)
	before := certs(t, e)
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home2"}})
	if err := e.svc.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	_, cmd := e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": "Idle"})
	for i := 0; i < 10 && cmd != nil; i++ {
		st := "Acknowledged"
		if isWiFi(cmd) {
			st = "Error"
		}
		_, cmd = e.put(t, c, PathServer, map[string]any{"UDID": "UDID-1", "Status": st, "CommandUUID": cmd["CommandUUID"]})
	}
	cmds, _ := e.store.ListCommands(ctx, e.dev.ID, 100)
	for _, x := range cmds {
		if x.Purpose == purposeWiFi && x.State == core.CommandFailed && x.Data != "" {
			t.Fatal("key kept")
		}
	}
	if got := certs(t, e); len(got) != 2 || !slices.Contains(got, before[0]) {
		t.Fatal(got)
	}
	if m, _ := e.store.GetManaged(ctx, e.dev.ID); m.PolicyCompliant {
		t.Fatalf("%+v", m)
	}
}

// 管理が外れたら、配った証明書を取り消す。
func TestWiFiRevokedOnCheckOut(t *testing.T) {
	e := newWiFiEnv(t)
	e.setWiFi(t, []core.WiFiNetwork{{SSID: "home"}})
	c := e.enroll(t)
	e.checkIn(t, c)
	e.drain(t, c)
	if len(certs(t, e)) != 1 {
		t.Fatal("no cert")
	}
	e.put(t, c, PathCheckIn, map[string]any{"MessageType": "CheckOut", "UDID": "UDID-1"})
	if got := certs(t, e); len(got) != 0 {
		t.Fatal(got)
	}
}
