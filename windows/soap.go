package windows

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// 登録（MS-MDE2）の SOAP のメッセージ。必要な項目だけを読む。名前空間は見ずに要素の名前で読む。
type envelope struct {
	Header struct {
		Action    string `xml:"Action"`
		MessageID string `xml:"MessageID"`
		Security  struct {
			UsernameToken struct {
				Username string `xml:"Username"`
				Password string `xml:"Password"`
			} `xml:"UsernameToken"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Discover *struct {
			Request struct {
				EmailAddress   string   `xml:"EmailAddress"`
				RequestVersion string   `xml:"RequestVersion"`
				AuthPolicies   []string `xml:"AuthPolicies>AuthPolicy"`
			} `xml:"request"`
		} `xml:"Discover"`
		GetPolicies *struct{} `xml:"GetPolicies"`
		RST         *struct {
			TokenType           string `xml:"TokenType"`
			RequestType         string `xml:"RequestType"`
			BinarySecurityToken struct {
				Value     string `xml:",chardata"`
				ValueType string `xml:"ValueType,attr"`
			} `xml:"BinarySecurityToken"`
			ContextItems []struct {
				Name  string `xml:"Name,attr"`
				Value string `xml:"Value"`
			} `xml:"AdditionalContext>ContextItem"`
		} `xml:"RequestSecurityToken"`
	} `xml:"Body"`
}

func (e *envelope) context(name string) string {
	if e.Body.RST == nil {
		return ""
	}
	for _, c := range e.Body.RST.ContextItems {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func parseEnvelope(b []byte) (*envelope, error) {
	var e envelope
	if err := xml.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("windows: SOAP が読めない: %w", err)
	}
	return &e, nil
}

const (
	nsSOAP        = "http://www.w3.org/2003/05/soap-envelope"
	nsAddressing  = "http://www.w3.org/2005/08/addressing"
	actionDisc    = "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse"
	actionPolicy  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
	actionEnroll  = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
	valuePKCS10   = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
	soapType      = "application/soap+xml; charset=utf-8"
	syncmlType    = "application/vnd.syncml.dm+xml"
	providerIDDef = "imohiyoko-mdm"
)

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{"x": xmlEscape}).Parse(`
{{define "discover"}}<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
<s:Header>
<a:Action s:mustUnderstand="1">` + actionDisc + `</a:Action>
<ActivityId CorrelationId="{{.Activity}}" xmlns="http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics">{{.Activity}}</ActivityId>
<a:RelatesTo>{{x .RelatesTo}}</a:RelatesTo>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
<DiscoverResult>
<AuthPolicy>OnPremise</AuthPolicy>
<EnrollmentVersion>{{x .Version}}</EnrollmentVersion>
<EnrollmentPolicyServiceUrl>{{x .PolicyURL}}</EnrollmentPolicyServiceUrl>
<EnrollmentServiceUrl>{{x .EnrollURL}}</EnrollmentServiceUrl>
</DiscoverResult>
</DiscoverResponse>
</s:Body>
</s:Envelope>{{end}}

{{define "policies"}}<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header>
<a:Action s:mustUnderstand="1">` + actionPolicy + `</a:Action>
<a:RelatesTo>{{x .RelatesTo}}</a:RelatesTo>
</s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
<response>
<policyID/>
<policyFriendlyName xsi:nil="true"/>
<nextUpdateHours xsi:nil="true"/>
<policiesNotChanged xsi:nil="true"/>
<policies>
<policy>
<policyOIDReference>0</policyOIDReference>
<cAs xsi:nil="true"/>
<attributes>
<commonName>mdm</commonName>
<policySchema>3</policySchema>
<certificateValidity>
<validityPeriodSeconds>{{.ValiditySeconds}}</validityPeriodSeconds>
<renewalPeriodSeconds>{{.RenewalSeconds}}</renewalPeriodSeconds>
</certificateValidity>
<permission>
<enroll>true</enroll>
<autoEnroll>false</autoEnroll>
</permission>
<privateKeyAttributes>
<minimalKeyLength>2048</minimalKeyLength>
<keySpec xsi:nil="true"/>
<keyUsageProperty xsi:nil="true"/>
<permissions xsi:nil="true"/>
<algorithmOIDReference xsi:nil="true"/>
<cryptoProviders xsi:nil="true"/>
</privateKeyAttributes>
<revision>
<majorRevision>101</majorRevision>
<minorRevision>0</minorRevision>
</revision>
<supersededPolicies xsi:nil="true"/>
<privateKeyFlags xsi:nil="true"/>
<subjectNameFlags xsi:nil="true"/>
<enrollmentFlags xsi:nil="true"/>
<generalFlags xsi:nil="true"/>
<hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
<rARequirements xsi:nil="true"/>
<keyArchivalAttributes xsi:nil="true"/>
<extensions xsi:nil="true"/>
</attributes>
</policy>
</policies>
</response>
<cAs xsi:nil="true"/>
<oIDs>
<oID>
<value>2.16.840.1.101.3.4.2.1</value>
<group>4</group>
<oIDReferenceID>0</oIDReferenceID>
<defaultName>szOID_NIST_sha256</defaultName>
</oID>
</oIDs>
</GetPoliciesResponse>
</s:Body>
</s:Envelope>{{end}}

{{define "enroll"}}<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<s:Header>
<a:Action s:mustUnderstand="1">` + actionEnroll + `</a:Action>
<a:RelatesTo>{{x .RelatesTo}}</a:RelatesTo>
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<u:Timestamp u:Id="_0">
<u:Created>{{.Created}}</u:Created>
<u:Expires>{{.Expires}}</u:Expires>
</u:Timestamp>
</o:Security>
</s:Header>
<s:Body>
<RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<RequestSecurityTokenResponse>
<TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
<DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>
<RequestedSecurityToken>
<BinarySecurityToken ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{{.ProvDoc}}</BinarySecurityToken>
</RequestedSecurityToken>
<RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
</RequestSecurityTokenResponse>
</RequestSecurityTokenResponseCollection>
</s:Body>
</s:Envelope>{{end}}

{{define "fault"}}<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
<s:Header>
<a:Action s:mustUnderstand="1">{{x .Action}}</a:Action>
<a:RelatesTo>{{x .RelatesTo}}</a:RelatesTo>
</s:Header>
<s:Body>
<s:Fault>
<s:Code>
<s:Value>s:Receiver</s:Value>
<s:Subcode><s:Value>{{.Subcode}}</s:Value></s:Subcode>
</s:Code>
<s:Reason><s:Text xml:lang="en-US">{{x .Reason}}</s:Text></s:Reason>
</s:Fault>
</s:Body>
</s:Envelope>{{end}}
`))

func render(name string, data any) []byte {
	var b bytes.Buffer
	if err := tmpl.ExecuteTemplate(&b, name, data); err != nil {
		panic(err) // テンプレートの誤り
	}
	return b.Bytes()
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func soapTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
