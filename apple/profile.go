package apple

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"howett.net/plist"

	"github.com/imohiyoko/mdm/core"
)

// 構成プロファイル（.mobileconfig）を組み立てる。

const (
	// EnrollIdentifier は登録のプロファイルの名前。これを消すと管理が外れる。
	EnrollIdentifier = "com.imohiyoko.mdm.enroll"
	policyIdentifier = "com.imohiyoko.mdm.policy"
	dnsIdentifier    = "com.imohiyoko.mdm.dns"
	wifiIdentifier   = "com.imohiyoko.mdm.wifi"
)

// stableUUID は名前から決まる UUID。毎回同じ値にして、同じ内容のプロファイルが同じ形になるようにする。
func stableUUID(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	h := hex.EncodeToString(s[:16])
	return strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

func configuration(identifier, name, deviceID string, payloads []map[string]any) map[string]any {
	return map[string]any{
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   identifier,
		"PayloadUUID":         stableUUID(deviceID, identifier),
		"PayloadDisplayName":  name,
		"PayloadOrganization": "mdm",
		"PayloadScope":        "System",
		"PayloadContent":      payloads,
	}
}

func payload(typ, identifier, deviceID string, fields map[string]any) map[string]any {
	p := map[string]any{
		"PayloadType":       typ,
		"PayloadVersion":    1,
		"PayloadIdentifier": identifier,
		"PayloadUUID":       stableUUID(deviceID, identifier),
	}
	for k, v := range fields {
		p[k] = v
	}
	return p
}

func encode(v any) []byte {
	b, err := plist.MarshalIndent(v, plist.XMLFormat, "\t")
	if err != nil {
		panic(err) // 組み立てた値は必ず書ける
	}
	return b
}

type enrollInput struct {
	DeviceID   string
	P12        []byte
	P12Pass    string
	Topic      string
	ServerURL  string
	CheckInURL string
}

// enrollProfile は登録のプロファイル。端末の証明書（PKCS#12）と MDM の設定を入れる。
func enrollProfile(in enrollInput) []byte {
	idUUID := stableUUID(in.DeviceID, EnrollIdentifier+".identity")
	return encode(configuration(EnrollIdentifier, "MDM への登録", in.DeviceID, []map[string]any{
		payload("com.apple.security.pkcs12", EnrollIdentifier+".identity", in.DeviceID, map[string]any{
			"PayloadDisplayName": "端末の証明書",
			"PayloadContent":     in.P12,
			"Password":           in.P12Pass,
		}),
		payload("com.apple.mdm", EnrollIdentifier+".mdm", in.DeviceID, map[string]any{
			"PayloadDisplayName":      "端末の管理",
			"IdentityCertificateUUID": idUUID,
			"Topic":                   in.Topic,
			"ServerURL":               in.ServerURL,
			"CheckInURL":              in.CheckInURL,
			"CheckOutWhenRemoved":     true,
			"SignMessage":             false,
			// 1（問い合わせ）〜4096 のすべて。アプリ・プロファイル・制限・初期化などを許す。
			"AccessRights": 8191,
		}),
	}))
}

// policyProfile は MDM のポリシーを制限のプロファイルにする。強い制限は監視モードの端末だけで効く。
func policyProfile(deviceID string, p core.Policy) []byte {
	r := p.Device
	restr := map[string]any{
		"PayloadDisplayName":           "制限",
		"allowCamera":                  !r.CameraDisabled,
		"allowScreenShot":              !r.ScreenCaptureDisabled,
		"allowEraseContentAndSettings": !r.FactoryResetDisabled,
		"allowVPNCreation":             !r.VPNConfigDisabled,
	}
	if len(p.AppleApps.Blocked) > 0 && p.AppleApps.Mode != core.AppsAllowlist {
		restr["blockedAppBundleIDs"] = p.AppleApps.Blocked
	}
	if p.AppleApps.Mode == core.AppsAllowlist {
		restr["allowListedAppBundleIDs"] = p.AppleApps.Allowed
	}
	payloads := []map[string]any{payload("com.apple.applicationaccess", policyIdentifier+".restrictions", deviceID, restr)}
	if r.PasscodeMinLength > 0 {
		payloads = append(payloads, payload("com.apple.mobiledevice.passwordpolicy", policyIdentifier+".passcode", deviceID, map[string]any{
			"PayloadDisplayName": "パスコード",
			"forcePIN":           true,
			"minLength":          r.PasscodeMinLength,
		}))
	}
	return encode(configuration(policyIdentifier, "ルール", deviceID, payloads))
}

// dnsProfile は通信フィルター（DoH）を端末に設定するプロファイル。監視モードの端末では外せない。
func dnsProfile(deviceID, dohURL string) []byte {
	return encode(configuration(dnsIdentifier, "通信フィルター", deviceID, []map[string]any{
		payload("com.apple.dnsSettings.managed", dnsIdentifier+".settings", deviceID, map[string]any{
			"PayloadDisplayName":  "通信フィルター",
			"DNSSettings":         map[string]any{"DNSProtocol": "HTTPS", "ServerURL": dohURL},
			"ProhibitDisablement": true,
		}),
	}))
}

type wifiInput struct {
	DeviceID   string
	P12        []byte
	P12Pass    string
	CA         []byte // ネットワークの認証局（DER）
	ServerName string
	Networks   []core.WiFiNetwork
}

// wifiProfile は証明書で入る Wi-Fi（EAP-TLS）のプロファイル。ネットワークの認証局と端末の証明書と、ネットワークごとの設定を入れる。
// 端末はサーバーの証明書を、この認証局が発行した ServerName のものだけ信じる。
func wifiProfile(in wifiInput) []byte {
	rootUUID := stableUUID(in.DeviceID, wifiIdentifier+".ca")
	idUUID := stableUUID(in.DeviceID, wifiIdentifier+".identity")
	payloads := []map[string]any{
		payload("com.apple.security.root", wifiIdentifier+".ca", in.DeviceID, map[string]any{
			"PayloadDisplayName": "Wi-Fi の認証局",
			"PayloadContent":     in.CA,
		}),
		payload("com.apple.security.pkcs12", wifiIdentifier+".identity", in.DeviceID, map[string]any{
			"PayloadDisplayName": "Wi-Fi の端末の証明書",
			"PayloadContent":     in.P12,
			"Password":           in.P12Pass,
		}),
	}
	for _, n := range in.Networks {
		payloads = append(payloads, payload("com.apple.wifi.managed", wifiIdentifier+".network."+n.SSID, in.DeviceID, map[string]any{
			"PayloadDisplayName":     "Wi-Fi " + n.SSID,
			"SSID_STR":               n.SSID,
			"HIDDEN_NETWORK":         n.Hidden,
			"AutoJoin":               true,
			"EncryptionType":         "Any", // EAP の設定があるので Enterprise（WPA2・WPA3）
			"PayloadCertificateUUID": idUUID,
			"EAPClientConfiguration": map[string]any{
				"AcceptEAPTypes":               []int{13}, // EAP-TLS
				"UserName":                     in.DeviceID,
				"PayloadCertificateAnchorUUID": []string{rootUUID},
				"TLSTrustedServerNames":        []string{in.ServerName},
				"TLSMinimumVersion":            "1.2",
			},
		}))
	}
	return encode(configuration(wifiIdentifier, "Wi-Fi", in.DeviceID, payloads))
}

// command は MDM の命令（Command の辞書）を plist にする。
func command(requestType string, fields map[string]any) string {
	c := map[string]any{"RequestType": requestType}
	for k, v := range fields {
		c[k] = v
	}
	return string(encode(c))
}

func installProfile(profile []byte) string {
	return command("InstallProfile", map[string]any{"Payload": profile})
}

func describe(v any) string { return fmt.Sprint(v) }
