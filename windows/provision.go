package windows

import (
	"crypto/sha1" //nolint:gosec // Windows の証明書ストアの名前に使う（安全のためではない）
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"net/url"
	"strconv"
	"strings"
)

// thumbprint は Windows の証明書ストアでの名前（SHA-1 の 16 進の大文字）。
func thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// 登録の答えに入れる wap-provisioningdoc。端末に証明書・管理のサーバーの場所・通信の間隔を設定する。

type parm struct {
	Name     string `xml:"name,attr"`
	Value    string `xml:"value,attr"`
	Datatype string `xml:"datatype,attr,omitempty"`
}

type characteristic struct {
	Type     string           `xml:"type,attr"`
	Parms    []parm           `xml:"parm"`
	Children []characteristic `xml:"characteristic"`
}

type provisioningDoc struct {
	XMLName  xml.Name         `xml:"wap-provisioningdoc"`
	Version  string           `xml:"version,attr"`
	Children []characteristic `xml:"characteristic"`
}

func ch(typ string, parms []parm, children ...characteristic) characteristic {
	return characteristic{Type: typ, Parms: parms, Children: children}
}

type provisionInput struct {
	CACert      []byte // 認証局の証明書（DER）
	ClientCert  []byte // 端末の証明書（DER）
	DeviceStore bool   // 端末の証明書を System に置くか（false なら User）
	DeviceID    string // MDM の端末の ID（証明書の CN）
	ManageURL   string
	ProviderID  string
	ServerName  string // 設定の画面に出る名前
	PollMinutes int
	DigestUser  string // 使わないが、仕様の例にそろえて置く
	DigestPass  string
}

func buildProvisioningDoc(in provisionInput) string {
	store := "User"
	if in.DeviceStore {
		store = "System"
	}
	certs := ch("CertificateStore", nil,
		ch("Root", nil, ch("System", nil, ch(thumbprint(in.CACert), []parm{{Name: "EncodedCertificate", Value: base64.StdEncoding.EncodeToString(in.CACert)}}))),
		ch("My", nil, ch(store, nil,
			ch(thumbprint(in.ClientCert), []parm{{Name: "EncodedCertificate", Value: base64.StdEncoding.EncodeToString(in.ClientCert)}}),
			ch("PrivateKeyContainer", nil),
		)),
	)
	// 管理のサーバーとの TLS で、この証明書を使わせる。
	criteria := "Subject=" + url.QueryEscape("CN="+in.DeviceID) + "&Stores=" + url.QueryEscape(`MY\`+store)
	app := ch("APPLICATION", []parm{
		{Name: "APPID", Value: "w7"},
		{Name: "PROVIDER-ID", Value: in.ProviderID},
		{Name: "NAME", Value: in.ServerName},
		{Name: "ADDR", Value: in.ManageURL},
		{Name: "CONNRETRYFREQ", Value: "6"},
		{Name: "INITIALBACKOFFTIME", Value: "30000"},
		{Name: "MAXBACKOFFTIME", Value: "120000"},
		{Name: "BACKCOMPATRETRYDISABLED", Value: ""},
		{Name: "DEFAULTENCODING", Value: syncmlType},
		{Name: "SSLCLIENTCERTSEARCHCRITERIA", Value: criteria},
	},
		ch("APPAUTH", []parm{{Name: "AAUTHLEVEL", Value: "CLIENT"}, {Name: "AAUTHTYPE", Value: "DIGEST"}, {Name: "AAUTHSECRET", Value: in.DigestPass}, {Name: "AAUTHDATA", Value: "bm9uY2U="}}),
		ch("APPAUTH", []parm{{Name: "AAUTHLEVEL", Value: "APPSRV"}, {Name: "AAUTHTYPE", Value: "DIGEST"}, {Name: "AAUTHNAME", Value: in.DigestUser}, {Name: "AAUTHSECRET", Value: in.DigestPass}, {Name: "AAUTHDATA", Value: "bm9uY2U="}}),
	)
	poll := strconv.Itoa(in.PollMinutes)
	dm := ch("DMClient", nil, ch("Provider", nil, ch(in.ProviderID, []parm{
		{Name: "EntDMID", Value: in.DeviceID, Datatype: "string"},
	}, ch("Poll", []parm{
		// 最初の組の回数を 0（ずっと）にし、PollMinutes ごとに通信させる。
		{Name: "NumberOfFirstRetries", Value: "0", Datatype: "integer"},
		{Name: "IntervalForFirstSetOfRetries", Value: poll, Datatype: "integer"},
		{Name: "NumberOfSecondRetries", Value: "0", Datatype: "integer"},
		{Name: "IntervalForSecondSetOfRetries", Value: "0", Datatype: "integer"},
		{Name: "NumberOfRemainingScheduledRetries", Value: "0", Datatype: "integer"},
		{Name: "IntervalForRemainingScheduledRetries", Value: "0", Datatype: "integer"},
		{Name: "PollOnLogin", Value: "true", Datatype: "boolean"},
		{Name: "AllUsersPollOnFirstLogin", Value: "true", Datatype: "boolean"},
	}))))
	doc := provisioningDoc{Version: "1.1", Children: []characteristic{certs, app, dm}}
	b, err := xml.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
