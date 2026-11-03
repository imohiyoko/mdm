package windows

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/pki"
)

// Wi-Fi（EAP-TLS）の配布。ネットワークの認証局（RootCATrustedCertificates）・端末の証明書（ClientCertificateInstall の PFX）・
// ネットワークごとの設定（WiFi の WlanXml）を入れる。どれも端末（コンピューター）の側に入れ、コンピューターの証明書で入る。

const (
	purposeWiFi = "wifi"

	uriRootCA   = "./Device/Vendor/MSFT/RootCATrustedCertificates/Root/"
	uriPFX      = "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/"
	uriWiFi     = "./Device/Vendor/MSFT/WiFi/Profile/"
	pfxBlobLeaf = "/PFXCertBlob"
)

// wifiRenewBefore より期限が近づいたら、端末の証明書を新しくして配り直す。
const wifiRenewBefore = 30 * 24 * time.Hour

// pfxID は端末の証明書の PFXCertInstall の名前。指紋から決まるので、前の証明書の名前も分かる。
func pfxID(fingerprint string) string { return "mdm-wifi-" + fingerprint[:16] }

func wifiHash(nets []core.WiFiNetwork, serverName, caFingerprint string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%q %q", serverName, caFingerprint)
	for _, n := range nets {
		fmt.Fprintf(h, " %q %t", n.SSID, n.Hidden)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// spacedThumbprint は拇印を 2 文字ずつ空けた小文字（WLAN のプロファイルの書き方）。
func spacedThumbprint(der []byte) string {
	t := strings.ToLower(thumbprint(der))
	parts := make([]string, 0, len(t)/2)
	for i := 0; i < len(t); i += 2 {
		parts = append(parts, t[i:i+2])
	}
	return strings.Join(parts, " ")
}

// wlanXML は EAP-TLS の Wi-Fi の設定（WLAN のプロファイル）。サーバーは serverName の名前と認証局で確かめ、
// 端末の証明書はその認証局が発行したものだけを使う。caDER は認証局の証明書。
func wlanXML(n core.WiFiNetwork, serverName string, caDER []byte) string {
	esc := xmlEscape
	pairs := spacedThumbprint(caDER)
	return `<?xml version="1.0"?>` +
		`<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">` +
		`<name>` + esc(n.SSID) + `</name>` +
		`<SSIDConfig><SSID><hex>` + strings.ToUpper(hex.EncodeToString([]byte(n.SSID))) + `</hex><name>` + esc(n.SSID) + `</name></SSID>` +
		fmt.Sprintf(`<nonBroadcast>%t</nonBroadcast></SSIDConfig>`, n.Hidden) +
		`<connectionType>ESS</connectionType><connectionMode>auto</connectionMode>` +
		`<MSM><security><authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>` +
		`<OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>machine</authMode><EAPConfig>` +
		`<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">` +
		`<EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommonTypes">13</Type>` +
		`<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommonTypes">0</VendorId>` +
		`<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommonTypes">0</VendorType>` +
		`<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommonTypes">0</AuthorId></EapMethod>` +
		`<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">` +
		`<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type>` +
		`<EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">` +
		`<CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>` +
		`<ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>` +
		`<ServerNames>` + esc(serverName) + `</ServerNames><TrustedRootCA>` + pairs + `</TrustedRootCA></ServerValidation>` +
		`<DifferentUsername>false</DifferentUsername>` +
		`<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>` +
		`<AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>` +
		`<TLSExtensions xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">` +
		`<FilteringInfo xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3"><CAHashList Enabled="true"><IssuerHash>` + pairs + `</IssuerHash></CAHashList></FilteringInfo>` +
		`</TLSExtensions></EapType></Eap></Config></EapHostConfig></EAPConfig></OneX></security></MSM></WLANProfile>`
}

func wifiURI(ssid string) string { return uriWiFi + url.PathEscape(ssid) }

// queueWiFi はポリシーの wifi が変わったら（証明書の期限が近づいたときも）、Wi-Fi の設定と新しい端末の証明書を配る。
// 前の証明書は、新しいものを入れたと端末が答えてから消して取り消す。無くなったネットワークの設定は消す。
// 管理の API で証明書を取り消した端末には、設定が変わるまで配り直さない。
func (s *Service) queueWiFi(ctx context.Context, m *core.Managed, d core.Device, now time.Time) error {
	if s.Network == nil {
		return nil
	}
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return err
	}
	var cmds []core.DeviceCommand
	add := func(verb, uri, format, data string) {
		cmds = append(cmds, core.DeviceCommand{DeviceID: d.ID, Verb: verb, LocURI: uri, Format: format, Data: data, Purpose: purposeWiFi, CreatedAt: now})
	}
	var keep []string
	for _, n := range pol.WiFi {
		keep = append(keep, n.SSID)
	}
	for _, old := range m.WiFiSSIDs {
		if !slices.Contains(keep, old) {
			add("Delete", wifiURI(old), "", "")
		}
	}
	if len(pol.WiFi) == 0 {
		if m.WiFiHash == "" {
			return nil
		}
		if m.WiFiCert != "" {
			add("Delete", uriPFX+pfxID(m.WiFiCert), "", "")
		}
		if _, err := s.Store.EnqueueCommands(ctx, cmds); err != nil {
			return err
		}
		m.WiFiHash, m.WiFiCert, m.WiFiSSIDs = "", "", nil
		_, err := s.Store.DeleteNetworkCerts(ctx, d.ID)
		return err
	}
	h := wifiHash(pol.WiFi, s.Network.ServerName, pki.Fingerprint(s.Network.CA.Cert))
	if h == m.WiFiHash {
		c, err := s.Store.GetNetworkCert(ctx, m.WiFiCert)
		if errors.Is(err, core.ErrNotFound) {
			return nil // 取り消された
		}
		if err != nil {
			return err
		}
		if c.NotAfter.Sub(now) > wifiRenewBefore {
			return nil
		}
	}
	iss, err := s.Network.Issue(ctx, d.ID, false)
	if err != nil {
		return err
	}
	ca := s.Network.CA.Cert
	fp := pki.Fingerprint(iss.Cert)
	pfx := uriPFX + pfxID(fp)
	add("Add", uriRootCA+thumbprint(ca.Raw)+"/EncodedCertificate", "b64", base64.StdEncoding.EncodeToString(ca.Raw))
	add("Add", pfx+"/KeyLocation", "int", "2") // TPM があれば TPM、無ければソフトウェア
	add("Add", pfx+"/PFXKeyExportable", "bool", "false")
	add("Add", pfx+"/PFXCertPasswordEncryptionType", "int", "0")
	add("Add", pfx+"/PFXCertPassword", "chr", iss.Password)
	add("Add", pfx+pfxBlobLeaf, "chr", base64.StdEncoding.EncodeToString(iss.PKCS12))
	for _, n := range pol.WiFi {
		verb := "Add"
		if slices.Contains(m.WiFiSSIDs, n.SSID) {
			verb = "Replace"
		}
		add(verb, wifiURI(n.SSID)+"/WlanXml", "chr", wlanXML(n, s.Network.ServerName, ca.Raw))
	}
	if _, err := s.Store.EnqueueCommands(ctx, cmds); err != nil {
		return err
	}
	m.WiFiHash, m.WiFiCert, m.WiFiSSIDs = h, fp, keep
	return nil
}

// onWiFiStatus は Wi-Fi の命令の答え。
func (s *Service) onWiFiStatus(ctx context.Context, m *core.Managed, cmd core.DeviceCommand, code string, now time.Time) error {
	// 鍵の合言葉と PFX は残さない。
	if cmd.Verb != "Delete" && cmd.Format != "" {
		if err := s.Store.ClearCommandData(ctx, m.DeviceID, cmd.ID); err != nil {
			return err
		}
	}
	switch {
	case code == "418" && cmd.Verb == "Add" && strings.HasSuffix(cmd.LocURI, "/WlanXml"):
		// もうある設定は置き換える。
		_, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{{
			DeviceID: m.DeviceID, Verb: "Replace", LocURI: cmd.LocURI, Format: cmd.Format, Data: cmd.Data, Purpose: purposeWiFi, CreatedAt: now,
		}})
		return err
	case code == "418" && strings.HasPrefix(cmd.LocURI, uriRootCA):
		return nil // 認証局はもう入っている
	case code != "200" && code != "202" && !(cmd.Verb == "Delete" && code == "404"):
		m.Problems = appendUnique(m.Problems, "wifi "+cmd.LocURI+": "+code)
		return nil
	}
	if m.WiFiCert == "" || cmd.Verb != "Add" || !strings.HasSuffix(cmd.LocURI, pfxBlobLeaf) || !strings.HasPrefix(cmd.LocURI, uriPFX+pfxID(m.WiFiCert)+"/") {
		return nil
	}
	// 新しい証明書が入ったので、前の証明書を端末から消し、取り消す。
	olds, err := s.Store.ListNetworkCerts(ctx, m.DeviceID)
	if err != nil {
		return err
	}
	var dels []core.DeviceCommand
	for _, c := range olds {
		if c.Fingerprint != m.WiFiCert {
			dels = append(dels, core.DeviceCommand{DeviceID: m.DeviceID, Verb: "Delete", LocURI: uriPFX + pfxID(c.Fingerprint), Purpose: purposeWiFi, CreatedAt: now})
		}
	}
	if len(dels) > 0 {
		if _, err := s.Store.EnqueueCommands(ctx, dels); err != nil {
			return err
		}
	}
	_, err = s.Store.DeleteNetworkCertsExcept(ctx, m.DeviceID, m.WiFiCert)
	return err
}

// revokeWiFi は MDM で配った Wi-Fi の証明書を取り消す（管理が外れたとき）。
func (s *Service) revokeWiFi(ctx context.Context, m *core.Managed) error {
	if m.WiFiHash == "" && m.WiFiCert == "" {
		return nil
	}
	m.WiFiHash, m.WiFiCert, m.WiFiSSIDs = "", "", nil
	_, err := s.Store.DeleteNetworkCerts(ctx, m.DeviceID)
	return err
}
