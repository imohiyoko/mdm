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
// supervised と ios は端末が監視モードの iPhone・iPad か。組み込みの Web のフィルターはそのときだけ入れる
// （Mac は組み込みの型を持たず、監視モードでない iPhone・iPad はプラグインの型しか入れられないので、入れるとプロファイルごと失敗する）。
func policyProfile(deviceID string, p core.Policy, supervised, ios bool) []byte {
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
	safariRestrictions(restr, p.Safari)
	payloads := []map[string]any{payload("com.apple.applicationaccess", policyIdentifier+".restrictions", deviceID, restr)}
	if supervised && ios && p.WebFilter.Enabled() {
		payloads = append(payloads, webFilterPayload(deviceID, p.WebFilter))
	}
	if r.PasscodeMinLength > 0 {
		payloads = append(payloads, payload("com.apple.mobiledevice.passwordpolicy", policyIdentifier+".passcode", deviceID, map[string]any{
			"PayloadDisplayName": "パスコード",
			"forcePIN":           true,
			"minLength":          r.PasscodeMinLength,
		}))
	}
	return encode(configuration(policyIdentifier, "ルール", deviceID, payloads))
}

// safariRestrictions は Safari の制限を制限のペイロードに足す。止めるものだけを書く（書かないキーは端末の既定＝許す）。
// キーと対応 OS は Apple の device-management の mdm/profiles/com.apple.applicationaccess.yaml による。
// 端末が知らないキー（古い OS・Mac で iPhone だけのキー）は端末が無視する。
func safariRestrictions(restr map[string]any, s core.SafariRules) {
	if s.Disabled {
		restr["allowSafari"] = false // iOS（監視モード）
	}
	if s.PopupsBlocked {
		restr["safariAllowPopups"] = false // iOS
	}
	if s.FraudWarningForced {
		restr["safariForceFraudWarning"] = true // iOS
	}
	if s.AutoFillDisabled {
		restr["safariAllowAutoFill"] = false // iOS（監視モード）、macOS 10.13 以降
	}
	if s.PrivateBrowsingDisabled {
		restr["allowSafariPrivateBrowsing"] = false // iOS 26（監視モード）、macOS 26 以降
	}
	if s.CookiesBlocked {
		// 0: サイト越えの追跡を防ぎ、すべての Cookie を止める。利用者は戻せない。値は実数（<real>）。
		restr["safariAcceptCookies"] = 0.0 // iOS
	}
}

// webFilterPayload は組み込みの Web のフィルター（com.apple.webcontent-filter、FilterType BuiltIn）。
// AllowOnly があればそこだけを開けるようにし、無ければ大人向けのサイトの自動のフィルターと止める URL を使う。
func webFilterPayload(deviceID string, w core.WebFilterRules) map[string]any {
	f := map[string]any{
		"PayloadDisplayName": "Web のフィルター",
		"FilterType":         "BuiltIn",
	}
	if len(w.AllowOnly) > 0 {
		var items []map[string]any
		for _, b := range w.AllowOnly {
			items = append(items, map[string]any{"URL": b.URL, "Title": b.Title})
		}
		f["AllowListBookmarks"] = items
	} else {
		f["AutoFilterEnabled"] = w.LimitAdult
		if w.LimitAdult && len(w.Permitted) > 0 {
			f["PermittedURLs"] = w.Permitted // AutoFilterEnabled が true のときだけ意味がある
		}
		if len(w.Denied) > 0 {
			f["DenyListURLs"] = w.Denied // 500 件まで（管理の API で絞る）
		}
	}
	return payload("com.apple.webcontent-filter", policyIdentifier+".webfilter", deviceID, f)
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
