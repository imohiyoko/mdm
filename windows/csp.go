package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/imohiyoko/mdm/core"
)

// setting は端末に配る CSP（Windows の設定の項目）の 1 つ。
type setting struct {
	Verb   string
	URI    string
	Format string
	Data   string
}

const appLockerNode = "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/mdm"

// buildSettings は MDM のポリシーを Windows の設定にする。値は毎回すべて書く（前の値を消すため）。
func buildSettings(p core.Policy) []setting {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	r := p.Device
	out := []setting{
		{"Replace", "./Device/Vendor/MSFT/Policy/Config/Camera/AllowCamera", "int", b(!r.CameraDisabled)},
		// 子どもが設定から管理を外せないようにする（Windows には「初期化の禁止」の代わりにこれを使う）。
		{"Replace", "./Device/Vendor/MSFT/Policy/Config/Experience/AllowManualMDMUnenrollment", "int", b(!r.FactoryResetDisabled)},
	}
	if r.PasscodeMinLength > 0 {
		out = append(out,
			setting{"Replace", "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordEnabled", "int", "0"}, // 0 が「必須」
			setting{"Replace", "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength", "int", strconv.Itoa(r.PasscodeMinLength)},
		)
	} else {
		out = append(out, setting{"Replace", "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordEnabled", "int", "1"})
	}
	if len(p.WindowsApps.Blocked) > 0 {
		out = append(out, setting{"Replace", appLockerNode + "/StoreApps/Policy", "chr", appLockerStoreApps(p.WindowsApps.Blocked)})
	} else {
		// 何も止めないなら規則ごと消す（無ければ 404 が返るが、それでよい）。
		out = append(out, setting{"Delete", appLockerNode, "", ""})
	}
	return out
}

func settingsHash(ss []setting) string {
	h := sha256.New()
	for _, s := range ss {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00", s.Verb, s.URI, s.Format, s.Data)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// ruleID は規則の ID（名前から決まる GUID の形）。毎回同じ値にして、配り直しても変わらないようにする。
func ruleID(name string) string {
	s := sha256.Sum256([]byte(name))
	h := hex.EncodeToString(s[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// appLockerStoreApps は Microsoft Store のアプリ（パッケージ名）を止める AppLocker の規則。
// 規則が 1 つでもあると、ほかのアプリは止まるので、署名されたアプリをすべて許す規則を先に置く。
func appLockerStoreApps(blocked []string) string {
	var b strings.Builder
	b.WriteString(`<RuleCollection Type="Appx" EnforcementMode="Enabled">`)
	fmt.Fprintf(&b, `<FilePublisherRule Id="%s" Name="mdm: allow signed packaged apps" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">`+
		`<Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>`,
		ruleID("allow-all"))
	for _, name := range blocked {
		fmt.Fprintf(&b, `<FilePublisherRule Id="%s" Name="mdm: block %s" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">`+
			`<Conditions><FilePublisherCondition PublisherName="*" ProductName="%s" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>`,
			ruleID("deny:"+name), xmlEscape(name), xmlEscape(name))
	}
	b.WriteString(`</RuleCollection>`)
	return b.String()
}

// 端末の情報を問い合わせる項目。
const (
	uriOSVersion  = "./DevDetail/SwV"
	uriMan        = "./DevInfo/Man"
	uriMod        = "./DevInfo/Mod"
	uriDeviceName = "./DevDetail/Ext/Microsoft/DeviceName"
	uriEdition    = "./DevDetail/Ext/Microsoft/OSPlatform"
	uriEncryption = "./Vendor/MSFT/DeviceStatus/Compliance/EncryptionCompliance"
)

var inventoryURIs = []string{uriOSVersion, uriMan, uriMod, uriDeviceName, uriEdition, uriEncryption}

// 命令の目的。
const (
	purposePolicy    = "policy"
	purposeInventory = "inventory"
	purposeReboot    = "reboot"
	purposeWipe      = "wipe"
	purposeUnenroll  = "unenroll"
)
