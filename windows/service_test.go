package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/pki"
)

const discoverReq = `<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
<a:MessageID>urn:uuid:748132ec-a575-4329-b01b-6171a9cf8478</a:MessageID></s:Header>
<s:Body><Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment"><request xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
<EmailAddress>device@mdm.example</EmailAddress><RequestVersion>5.0</RequestVersion><DeviceType>CIMClient_Windows</DeviceType>
<AuthPolicies><AuthPolicy>OnPremise</AuthPolicy><AuthPolicy>Federated</AuthPolicy></AuthPolicies></request></Discover></s:Body></s:Envelope>`

const policyReq = `<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
<a:MessageID>urn:uuid:72048B64-0F19-448F-8C2E-B4C661860AA0</a:MessageID>
<wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:UsernameToken><wsse:Username>device@mdm.example</wsse:Username><wsse:Password wsse:Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%s</wsse:Password></wsse:UsernameToken>
</wsse:Security></s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
<client><lastUpdate xsi:nil="true"/><preferredLanguage xsi:nil="true"/></client><requestFilter xsi:nil="true"/></GetPolicies></s:Body></s:Envelope>`

const enrollReq = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
<a:MessageID>urn:uuid:0d5a1441-5891-453b-becf-a2e5f6ea3749</a:MessageID>
<wsse:Security s:mustUnderstand="1"><wsse:UsernameToken><wsse:Username>device@mdm.example</wsse:Username><wsse:Password>%s</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body><wst:RequestSecurityToken>
<wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">%s</wsse:BinarySecurityToken>
<ac:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
<ac:ContextItem Name="DeviceID"><ac:Value>AB157C3A18778F4FB21E2739066C1F27</ac:Value></ac:ContextItem>
<ac:ContextItem Name="EnrollmentType"><ac:Value>Full</ac:Value></ac:ContextItem>
<ac:ContextItem Name="OSVersion"><ac:Value>10.0.26100.1</ac:Value></ac:ContextItem>
</ac:AdditionalContext></wst:RequestSecurityToken></s:Body></s:Envelope>`

type env struct {
	svc   *Service
	store core.Store
	clock *testkit.Clock
	dev   core.Device
	srv   *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store := testkit.Store(t)
	// 認証局は本当の時刻で作るので、テストの時計も今に合わせる（固定の日時だと、その 1 時間後から証明書がまだ有効でなくなる）。
	clock := testkit.NewClock(time.Now().UTC().Truncate(time.Second))
	ca, err := pki.NewCA("test CA", 2048)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.CreatePolicy(ctx, core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	_, h1 := core.NewFilterToken()
	_, h2 := core.NewFilterToken()
	d := core.Device{ID: "dev_w", OrgID: testkit.OrgID, Name: "ノート PC", Platform: core.PlatformWindows, FilterTokenHash: h1, DoTLabelHash: h2}
	if err := store.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: store, Engine: &filter.Engine{Store: store, Clock: clock}, Clock: clock, CA: ca, BaseURL: "https://mdm.example", Logger: slog.New(slog.DiscardHandler)}
	srv := httptest.NewUnstartedServer(svc.Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{svc, store, clock, d, srv}
}

func (e *env) post(t *testing.T, c *http.Client, path, body string) (int, string) {
	t.Helper()
	if c == nil {
		c = e.srv.Client()
	}
	resp, err := c.Post(e.srv.URL+path, "application/soap+xml; charset=utf-8", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// enroll は登録を最後まで進め、端末の証明書を持ったクライアントを返す。
func (e *env) enroll(t *testing.T) *http.Client {
	t.Helper()
	en, err := e.svc.CreateEnrollment(context.Background(), e.dev, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "B1C43CD0-1624-5FBB-8E54-34CF17DFD3A1"}}, key)
	code, body := e.post(t, nil, PathEnrollment, fmt.Sprintf(enrollReq, strings.ToLower(en.Code), base64.StdEncoding.EncodeToString(csr)))
	if code != 200 {
		t.Fatal(code, body)
	}
	var resp struct {
		Token string `xml:"Body>RequestSecurityTokenResponseCollection>RequestSecurityTokenResponse>RequestedSecurityToken>BinarySecurityToken"`
	}
	if err := xml.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	docXML, err := base64.StdEncoding.DecodeString(resp.Token)
	if err != nil {
		t.Fatal(err)
	}
	var doc provisioningDoc
	if err := xml.Unmarshal(docXML, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Children[0].Type != "CertificateStore" || doc.Children[1].Type != "APPLICATION" || doc.Children[2].Type != "DMClient" {
		t.Fatal(string(docXML))
	}
	my := doc.Children[0].Children[1].Children[0] // My/User
	if my.Type != "User" {
		t.Fatal(my.Type)
	}
	der, _ := base64.StdEncoding.DecodeString(my.Children[0].Parms[0].Value)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := e.svc.CA.Verify(cert, e.clock.Now()); err != nil || id != e.dev.ID {
		t.Fatal(id, err)
	}
	if !strings.Contains(string(docXML), `value="https://mdm.example/ManagementServer/MDM.svc"`) ||
		!strings.Contains(string(docXML), `Subject=CN%3Ddev_w&amp;Stores=MY%5CUser`) {
		t.Fatal(string(docXML))
	}
	tr := e.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	return &http.Client{Transport: tr}
}

func TestEnrollment(t *testing.T) {
	e := newEnv(t)
	resp, err := e.srv.Client().Get(e.srv.URL + PathDiscovery)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	code, body := e.post(t, nil, PathDiscovery, discoverReq)
	if code != 200 || !strings.Contains(body, "<AuthPolicy>OnPremise</AuthPolicy>") ||
		!strings.Contains(body, "<EnrollmentServiceUrl>https://mdm.example/EnrollmentServer/Enrollment.svc</EnrollmentServiceUrl>") ||
		!strings.Contains(body, "urn:uuid:748132ec-a575-4329-b01b-6171a9cf8478") {
		t.Fatal(code, body)
	}
	// 端末の言う版は、知っている古い版だけを返す（XML に入れる値をそのまま返さない）。
	for req, want := range map[string]string{"3.0": "3.0", "3.00": "3.0", "5.0": "4.0", "1&lt;x/&gt;": "4.0", "2.0<x/>": "2.0"} {
		_, body := e.post(t, nil, PathDiscovery, strings.Replace(discoverReq, "<RequestVersion>5.0</RequestVersion>", "<RequestVersion>"+req+"</RequestVersion>", 1))
		if !strings.Contains(body, "<EnrollmentVersion>"+want+"</EnrollmentVersion>") || strings.Contains(body, "<x/>") {
			t.Fatalf("%s: %s", req, body)
		}
	}

	if code, body := e.post(t, nil, PathPolicy, fmt.Sprintf(policyReq, "WRONG-CODE")); code != 500 || !strings.Contains(body, "s:Authentication") {
		t.Fatal(code, body)
	}
	en, _ := e.svc.CreateEnrollment(context.Background(), e.dev, time.Hour)
	if !strings.HasPrefix(en.Link, "ms-device-enrollment:?") || en.ServerURL != "https://mdm.example" || len(en.Code) != 17 {
		t.Fatalf("%+v", en)
	}
	if code, body := e.post(t, nil, PathPolicy, fmt.Sprintf(policyReq, en.Code)); code != 200 || !strings.Contains(body, "<minimalKeyLength>2048</minimalKeyLength>") {
		t.Fatal(code, body)
	}
	e.clock.Advance(2 * time.Hour)
	if code, _ := e.post(t, nil, PathPolicy, fmt.Sprintf(policyReq, en.Code)); code != 500 {
		t.Fatal("expired code accepted")
	}

	e.enroll(t)
	m, err := e.store.GetManaged(context.Background(), e.dev.ID)
	if err != nil || m.State != core.ManagedPending || m.ExternalID != "AB157C3A18778F4FB21E2739066C1F27" || len(m.CertFingerprints) != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	// 合言葉は使い切り。
	if n, _ := e.store.ListCommands(context.Background(), e.dev.ID, 10); len(n) != 0 {
		t.Fatal(n)
	}
}

// msg は端末からのメッセージを作る。
func msg(msgID string, body string) string {
	return `<SyncML xmlns="SYNCML:SYNCML1.2"><SyncHdr><VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto><SessionID>1</SessionID><MsgID>` + msgID +
		`</MsgID><Target><LocURI>https://mdm.example/ManagementServer/MDM.svc</LocURI></Target><Source><LocURI>AB157C3A</LocURI></Source></SyncHdr><SyncBody>` +
		body + `<Final/></SyncBody></SyncML>`
}

const start = `<Alert><CmdID>2</CmdID><Data>1201</Data></Alert>
<Replace><CmdID>3</CmdID><Item><Source><LocURI>./DevInfo/DevId</LocURI></Source><Data>AB157C3A</Data></Item></Replace>`

func (e *env) manage(t *testing.T, c *http.Client, m string) (int, *syncML) {
	t.Helper()
	resp, err := c.Post(e.srv.URL+PathManagement, syncmlType, strings.NewReader(m))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	out, err := parseSyncML(b)
	if err != nil {
		t.Fatal(err, string(b))
	}
	return 200, out
}

func commands(m *syncML) []syncCmd {
	var out []syncCmd
	for _, c := range m.Body.Cmds {
		if c.XMLName.Local != "Status" {
			out = append(out, c)
		}
	}
	return out
}

// answer は送られたコマンドにすべて答える。fail の LocURI には 500、results の LocURI には値を返す。
func answer(cmds []syncCmd, fail map[string]bool, results map[string]string) string {
	var b bytes.Buffer
	n := 10
	for _, c := range cmds {
		uri := c.Items[0].Target.LocURI
		code := "200"
		if fail[uri] {
			code = "500"
		}
		fmt.Fprintf(&b, `<Status><CmdID>%d</CmdID><MsgRef>1</MsgRef><CmdRef>%s</CmdRef><Cmd>%s</Cmd><Data>%s</Data></Status>`, n, c.CmdID, c.XMLName.Local, code)
		n++
		if v, ok := results[uri]; ok && c.XMLName.Local == "Get" {
			fmt.Fprintf(&b, `<Results><CmdID>%d</CmdID><MsgRef>1</MsgRef><CmdRef>%s</CmdRef><Item><Source><LocURI>%s</LocURI></Source><Data>%s</Data></Item></Results>`, n, c.CmdID, uri, v)
			n++
		}
	}
	return b.String()
}

func TestManagement(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if code, _ := e.manage(t, e.srv.Client(), msg("1", start)); code != 401 {
		t.Fatal("no client certificate:", code)
	}
	c := e.enroll(t)

	code, out := e.manage(t, c, msg("1", start))
	if code != 200 {
		t.Fatal(code)
	}
	if out.Hdr.Target.LocURI != "AB157C3A" || out.Body.Cmds[0].Cmd != "SyncHdr" || out.Body.Cmds[1].CmdRef != "2" {
		t.Fatalf("%+v", out)
	}
	cmds := commands(out)
	uris := map[string]string{}
	for _, x := range cmds {
		uris[x.Items[0].Target.LocURI] = x.XMLName.Local
	}
	if uris["./Device/Vendor/MSFT/Policy/Config/Camera/AllowCamera"] != "Replace" || uris[uriOSVersion] != "Get" || uris[appLockerNode] != "Delete" {
		t.Fatal(uris)
	}

	code, out = e.manage(t, c, msg("2", answer(cmds,
		map[string]bool{"./Device/Vendor/MSFT/Policy/Config/Experience/AllowManualMDMUnenrollment": true},
		map[string]string{uriOSVersion: "10.0.26100.2033", uriMan: "Contoso", uriMod: "Laptop 7", uriEncryption: "1"})))
	if code != 200 || len(commands(out)) != 0 {
		t.Fatal(code, out)
	}
	m, _ := e.store.GetManaged(ctx, e.dev.ID)
	if m.State != core.ManagedActive || m.OSVersion != "10.0.26100.2033" || m.Model != "Contoso Laptop 7" || !m.Encrypted || m.PolicyCompliant ||
		len(m.Problems) != 1 || !strings.Contains(m.Problems[0], "AllowManualMDMUnenrollment: 500") {
		t.Fatalf("%+v", m)
	}

	// 変わっていなければ、次のやり取りでは何も送らない。
	e.clock.Advance(15 * time.Minute)
	if _, out = e.manage(t, c, msg("1", start)); len(commands(out)) != 0 {
		t.Fatal(commands(out))
	}

	// ポリシーを変えると、次のやり取りで配る。
	pol, _ := e.store.GetPolicy(ctx, filter.DefaultPolicyID)
	pol.WindowsApps.Blocked = []string{"Microsoft.MinecraftUWP"}
	pol.Device.CameraDisabled = true
	if err := e.store.UpdatePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Engine.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	_, out = e.manage(t, c, msg("1", start))
	cmds = commands(out)
	var applocker, camera string
	for _, x := range cmds {
		switch x.Items[0].Target.LocURI {
		case appLockerNode + "/StoreApps/Policy":
			applocker = x.Items[0].Data.text()
		case "./Device/Vendor/MSFT/Policy/Config/Camera/AllowCamera":
			camera = x.Items[0].Data.text()
		}
	}
	if !strings.Contains(applocker, `ProductName="Microsoft.MinecraftUWP"`) || !strings.Contains(applocker, `Action="Deny"`) || camera != "0" {
		t.Fatal(applocker, camera)
	}
	_, out = e.manage(t, c, msg("2", answer(cmds, nil, nil)))
	if m, _ = e.store.GetManaged(ctx, e.dev.ID); !m.PolicyCompliant || len(m.Problems) != 0 {
		t.Fatalf("%+v", m)
	}

	// 再起動の命令は、次のやり取りで送る。
	if err := e.svc.Command(ctx, e.dev, CommandReboot); err != nil {
		t.Fatal(err)
	}
	_, out = e.manage(t, c, msg("1", start))
	cmds = commands(out)
	if len(cmds) != 1 || cmds[0].XMLName.Local != "Exec" || cmds[0].Items[0].Target.LocURI != "./Device/Vendor/MSFT/Reboot/RebootNow" {
		t.Fatal(cmds)
	}
	// 答えが無ければ、しばらくしてから送り直す。
	e.clock.Advance(31 * time.Minute)
	if _, out = e.manage(t, c, msg("1", start)); len(commands(out)) != 1 {
		t.Fatal(commands(out))
	}
	e.manage(t, c, msg("2", answer(commands(out), nil, nil)))

	// 管理を外す。
	if err := e.svc.Unenroll(ctx, e.dev, false); err != nil {
		t.Fatal(err)
	}
	_, out = e.manage(t, c, msg("1", start))
	cmds = commands(out)
	if len(cmds) != 1 || cmds[0].Items[0].Target.LocURI != "./Device/Vendor/MSFT/DMClient/Provider/imohiyoko-mdm/Unenroll" {
		t.Fatal(cmds)
	}
	e.manage(t, c, msg("2", answer(cmds, nil, nil)))
	if m, _ = e.store.GetManaged(ctx, e.dev.ID); m.State != core.ManagedRemoved {
		t.Fatal(m.State)
	}
	if code, _ := e.manage(t, c, msg("1", start)); code != 401 {
		t.Fatal("removed device accepted:", code)
	}
}

func TestUserUnenroll(t *testing.T) {
	e := newEnv(t)
	c := e.enroll(t)
	e.manage(t, c, msg("1", start))
	_, out := e.manage(t, c, msg("1", `<Alert><CmdID>2</CmdID><Data>1226</Data><Item><Meta><Type xmlns="syncml:metinf">com.microsoft:mdm.unenrollment.userrequest</Type><Format xmlns="syncml:metinf">int</Format></Meta><Data>1</Data></Item></Alert>`))
	if len(commands(out)) != 0 {
		t.Fatal(commands(out))
	}
	if m, _ := e.store.GetManaged(context.Background(), e.dev.ID); m.State != core.ManagedRemoved || len(m.CertFingerprints) != 0 {
		t.Fatalf("%+v", m)
	}
}
