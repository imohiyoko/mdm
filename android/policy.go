package android

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/imohiyoko/mdm/core"
)

// managedFields は MDM が受け持つ AMAPI のポリシーの項目。配り直すときはこれだけを変える。
// 通信フィルターのホスト名（privateDnsSettings）は秘密を含み、サーバーは平文を持たないので、
// 登録のときと作り直したときだけ配る（ふだんの配り直しでは触らない）。
var managedFields = []string{
	"applications",
	"playStoreMode",
	"cameraAccess",
	"screenCaptureDisabled",
	"factoryResetDisabled",
	"vpnConfigDisabled",
	"passwordPolicies",
	"statusReportingSettings",
}

const dnsField = "deviceConnectivityManagement.privateDnsSettings"

// BuildPolicy は MDM のポリシーを AMAPI のポリシーにする。dotHost が空でなければ、
// 端末の Private DNS（DoT）をそのホストに固定する（完全管理の端末だけで効く）。
// 返す mask は PatchPolicy の updateMask。
func BuildPolicy(p core.Policy, dotHost string) (body map[string]any, mask []string) {
	body = map[string]any{}
	apps := []map[string]any{}
	add := func(pkgs []string, installType string) {
		for _, pkg := range pkgs {
			apps = append(apps, map[string]any{"packageName": pkg, "installType": installType})
		}
	}
	add(p.AndroidApps.Required, "FORCE_INSTALLED")
	add(p.AndroidApps.Allowed, "AVAILABLE")
	if p.AndroidApps.Mode == core.AppsAllowlist {
		// 載っていないアプリは入れられず、入っていれば消える。
		body["playStoreMode"] = "WHITELIST"
	} else {
		body["playStoreMode"] = "BLACKLIST"
		add(p.AndroidApps.Blocked, "BLOCKED")
	}
	body["applications"] = apps

	r := p.Device
	if r.CameraDisabled {
		body["cameraAccess"] = "CAMERA_ACCESS_DISABLED"
	} else {
		body["cameraAccess"] = "CAMERA_ACCESS_USER_CHOICE"
	}
	body["screenCaptureDisabled"] = r.ScreenCaptureDisabled
	body["factoryResetDisabled"] = r.FactoryResetDisabled
	body["vpnConfigDisabled"] = r.VPNConfigDisabled
	pw := []map[string]any{}
	if r.PasscodeMinLength > 0 {
		pw = append(pw, map[string]any{"passwordQuality": "NUMERIC_COMPLEX", "passwordMinimumLength": r.PasscodeMinLength})
	}
	body["passwordPolicies"] = pw
	// 準拠の判定に使う情報を報告させる。アプリの一覧は仕事用プロファイルでは仕事のアプリだけ。
	body["statusReportingSettings"] = map[string]any{
		"deviceSettingsEnabled":     true,
		"softwareInfoEnabled":       true,
		"applicationReportsEnabled": true,
	}
	mask = append(mask, managedFields...)
	if dotHost != "" {
		body["deviceConnectivityManagement"] = map[string]any{
			"privateDnsSettings": map[string]any{"privateDnsMode": "PRIVATE_DNS_SPECIFIED_HOST", "privateDnsHost": dotHost},
		}
		mask = append(mask, dnsField)
	}
	return body, mask
}

// policyHash はポリシーの要約。配ったものと同じかを見るのに使う。
func policyHash(body map[string]any) string {
	b, _ := json.Marshal(body) // map は鍵の順に並ぶ
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}
