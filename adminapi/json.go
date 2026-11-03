package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/imohiyoko/mdm/compliance"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{code, msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "")
	case errors.Is(err, core.ErrConflict):
		writeErr(w, http.StatusConflict, "conflict", "参照されている・同じものがある")
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "")
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	return true
}

type badRequest string

func (b badRequest) Error() string { return string(b) }

func bad(format string, a ...any) error { return badRequest(fmt.Sprintf(format, a...)) }

// --- people

type personJSON struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	Role      core.Role `json:"role"`
	PolicyID  string    `json:"policy_id,omitempty"`
	GroupIDs  []string  `json:"group_ids"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func toPersonJSON(p core.Person) personJSON {
	return personJSON{p.ID, p.OrgID, p.Name, p.Role, p.PolicyID, nonNil(p.GroupIDs), p.Email, p.CreatedAt}
}

type personInput struct {
	OrgID    *string    `json:"org_id"` // 作るときだけ
	Name     *string    `json:"name"`
	Role     *core.Role `json:"role"`
	PolicyID *string    `json:"policy_id"`
	GroupIDs *[]string  `json:"group_ids"`
	Email    *string    `json:"email"`
}

func (in personInput) apply(p *core.Person) error {
	if in.GroupIDs != nil {
		if len(*in.GroupIDs) > 100 {
			return bad("group_ids は 100 件まで")
		}
		p.GroupIDs = *in.GroupIDs
	}
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Role != nil {
		p.Role = *in.Role
	}
	if in.PolicyID != nil {
		p.PolicyID = *in.PolicyID
	}
	if in.Email != nil {
		p.Email = strings.ToLower(strings.TrimSpace(*in.Email))
		if p.Email != "" && !validEmail(p.Email) {
			return bad("email はメールアドレス（IAM に登録したもの）")
		}
	}
	if p.Name == "" || len(p.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if p.Role != core.RoleChild && p.Role != core.RoleAdult {
		return bad("role は child か adult")
	}
	return nil
}

// validEmail はおおまかなメールアドレスの形（IAM の側で確認済みのものと照らし合わせる）。
func validEmail(e string) bool {
	if len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>,;\"") {
		return false
	}
	local, domain, ok := strings.Cut(e, "@")
	return ok && local != "" && strings.Contains(domain, ".") && !strings.Contains(domain, "@") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

// --- devices

type deviceJSON struct {
	ID          string        `json:"id"`
	OrgID       string        `json:"org_id"`
	Name        string        `json:"name"`
	Platform    core.Platform `json:"platform"`
	PersonID    string        `json:"person_id,omitempty"`
	PolicyID    string        `json:"policy_id,omitempty"`
	PausedUntil *time.Time    `json:"paused_until,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	LastSeenAt  *time.Time    `json:"last_seen_at,omitempty"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toDeviceJSON(d core.Device, now time.Time) deviceJSON {
	var paused *time.Time
	if now.Before(d.PausedUntil) {
		paused = &d.PausedUntil
	}
	return deviceJSON{d.ID, d.OrgID, d.Name, d.Platform, d.PersonID, d.PolicyID, paused, d.CreatedAt, optTime(d.LastSeenAt)}
}

type deviceInput struct {
	OrgID    *string        `json:"org_id"` // 作るときだけ
	Name     *string        `json:"name"`
	Platform *core.Platform `json:"platform"`
	PersonID *string        `json:"person_id"`
	PolicyID *string        `json:"policy_id"`
}

func (in deviceInput) apply(d *core.Device) error {
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.Platform != nil {
		d.Platform = *in.Platform
	}
	if in.PersonID != nil {
		d.PersonID = *in.PersonID
	}
	if in.PolicyID != nil {
		d.PolicyID = *in.PolicyID
	}
	if d.Name == "" || len(d.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if !d.Platform.Valid() {
		return bad("platform は ios・android・windows・macos・other のどれか")
	}
	return nil
}

// --- policies

type windowJSON struct {
	Days  []string `json:"days,omitempty"` // "mon"〜"sun"。空なら毎日
	Start string   `json:"start"`          // "21:00"
	End   string   `json:"end"`            // "07:00"
}

type policyJSON struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"org_id,omitempty"`
	Name       string          `json:"name"`
	Mode       core.FilterMode `json:"mode"`
	Allow      []string        `json:"allow"`
	Block      []string        `json:"block"`
	Blocklists []string        `json:"blocklists"`
	QuietHours []windowJSON    `json:"quiet_hours"`
	TimeZone   string          `json:"time_zone,omitempty"`
	LogQueries bool            `json:"log_queries"`
	Device     deviceRulesJSON `json:"device"`
	Android    appRulesJSON    `json:"android_apps"`
	Windows    appRulesJSON    `json:"windows_apps"`
	Apple      appRulesJSON    `json:"apple_apps"`
	Compliance complianceJSON  `json:"compliance"`
	WiFi       []wifiJSON      `json:"wifi"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// wifiJSON は証明書で入る Wi-Fi のネットワーク。
type wifiJSON struct {
	SSID   string `json:"ssid"`
	Hidden bool   `json:"hidden"`
}

const maxWiFi = 16

func toWiFi(in []wifiJSON) ([]core.WiFiNetwork, error) {
	if len(in) > maxWiFi {
		return nil, bad("wifi は %d 件まで", maxWiFi)
	}
	var out []core.WiFiNetwork
	seen := map[string]bool{}
	for i, w := range in {
		if len(w.SSID) == 0 || len(w.SSID) > 32 || !utf8.ValidString(w.SSID) || strings.ContainsFunc(w.SSID, unicode.IsControl) {
			return nil, bad("wifi[%d].ssid は 1〜32 バイトの名前", i)
		}
		if seen[w.SSID] {
			return nil, bad("wifi の ssid %q が重なっている", w.SSID)
		}
		seen[w.SSID] = true
		out = append(out, core.WiFiNetwork(w))
	}
	return out, nil
}

type deviceRulesJSON struct {
	CameraDisabled        bool `json:"camera_disabled"`
	ScreenCaptureDisabled bool `json:"screen_capture_disabled"`
	FactoryResetDisabled  bool `json:"factory_reset_disabled"`
	VPNConfigDisabled     bool `json:"vpn_config_disabled"`
	PasscodeMinLength     int  `json:"passcode_min_length"`
}

type complianceJSON struct {
	RequireEncryption bool                     `json:"require_encryption"`
	RequireScreenLock bool                     `json:"require_screen_lock"`
	MaxReportAgeHours int                      `json:"max_report_age_hours"`
	MinOSVersion      map[core.Platform]string `json:"min_os_version"`
}

func (in complianceJSON) toRules() (core.ComplianceRules, error) {
	r := core.ComplianceRules(in)
	if r.MaxReportAgeHours < 0 || r.MaxReportAgeHours > 24*365 {
		return r, bad("compliance.max_report_age_hours は 0〜8760")
	}
	for pl, v := range r.MinOSVersion {
		if pl != core.PlatformAndroid && pl != core.PlatformIOS && pl != core.PlatformMacOS && pl != core.PlatformWindows {
			return r, bad("compliance.min_os_version の機種は android・ios・macos・windows")
		}
		if !compliance.ValidVersion(v) {
			return r, bad("compliance.min_os_version.%s は 17.4 のような版", pl)
		}
	}
	if len(r.MinOSVersion) == 0 {
		r.MinOSVersion = nil
	}
	return r, nil
}

type appRulesJSON struct {
	Mode     core.AppMode `json:"mode"`
	Required []string     `json:"required"`
	Allowed  []string     `json:"allowed"`
	Blocked  []string     `json:"blocked"`
}

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func formatClock(m core.TimeOfDay) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

func parseClock(s string) (core.TimeOfDay, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, bad("時刻は HH:MM（%q）", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || hh == 24 && mm != 0 {
		return 0, bad("時刻は HH:MM（%q）", s)
	}
	return core.TimeOfDay(hh*60 + mm), nil
}

func toPolicyJSON(p core.Policy) policyJSON {
	out := policyJSON{
		ID: p.ID, OrgID: p.OrgID, Name: p.Name, Mode: p.Mode, Allow: nonNil(p.Allow), Block: nonNil(p.Block),
		Blocklists: nonNil(p.ListIDs), QuietHours: []windowJSON{}, TimeZone: p.TimeZone,
		LogQueries: p.LogQueries, UpdatedAt: p.UpdatedAt,
		Device:     deviceRulesJSON(p.Device),
		Compliance: complianceJSON(p.Compliance),
		Android: appRulesJSON{Mode: p.AndroidApps.Mode, Required: nonNil(p.AndroidApps.Required),
			Allowed: nonNil(p.AndroidApps.Allowed), Blocked: nonNil(p.AndroidApps.Blocked)},
	}
	if out.Android.Mode == "" {
		out.Android.Mode = core.AppsOpen
	}
	out.Apple = appRulesJSON{Mode: p.AppleApps.Mode, Required: []string{},
		Allowed: nonNil(p.AppleApps.Allowed), Blocked: nonNil(p.AppleApps.Blocked)}
	if out.Apple.Mode == "" {
		out.Apple.Mode = core.AppsOpen
	}
	out.WiFi = []wifiJSON{}
	for _, w := range p.WiFi {
		out.WiFi = append(out.WiFi, wifiJSON(w))
	}
	out.Windows = appRulesJSON{Mode: core.AppsOpen, Required: []string{}, Allowed: []string{}, Blocked: nonNil(p.WindowsApps.Blocked)}
	for _, w := range p.Quiet {
		wj := windowJSON{Start: formatClock(w.Start), End: formatClock(w.End)}
		for _, d := range w.Days {
			wj.Days = append(wj.Days, dayNames[d])
		}
		out.QuietHours = append(out.QuietHours, wj)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type policyInput struct {
	OrgID      string          `json:"org_id"` // 作るときだけ。空ならサーバー全体のポリシー
	Name       string          `json:"name"`
	Mode       core.FilterMode `json:"mode"`
	Allow      []string        `json:"allow"`
	Block      []string        `json:"block"`
	Blocklists []string        `json:"blocklists"`
	QuietHours []windowJSON    `json:"quiet_hours"`
	TimeZone   string          `json:"time_zone"`
	LogQueries bool            `json:"log_queries"`
	Device     deviceRulesJSON `json:"device"`
	Android    appRulesJSON    `json:"android_apps"`
	Windows    appRulesJSON    `json:"windows_apps"`
	Apple      appRulesJSON    `json:"apple_apps"`
	Compliance complianceJSON  `json:"compliance"`
	WiFi       []wifiJSON      `json:"wifi"`
}

const maxPolicyDomains = 10000

const maxApps = 500

// androidPackage は Android のパッケージ名（com.example.app）。
var androidPackage = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

// appleBundleID は iPhone・Mac のアプリのバンドル ID（com.apple.mobilesafari）。
var appleBundleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9\-]*(\.[A-Za-z0-9][A-Za-z0-9\-]*)+$`)

// windowsPackage は Microsoft Store のアプリのパッケージ名（Microsoft.MinecraftUWP）。
var windowsPackage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]{2,99}$`)

// toWindowsRules は Windows のアプリのルール。いまは禁止の一覧だけを使える。
func (in appRulesJSON) toWindowsRules() (core.AppRules, error) {
	if in.Mode != "" && in.Mode != core.AppsOpen || len(in.Required) > 0 || len(in.Allowed) > 0 {
		return core.AppRules{}, bad("windows_apps は、いまは mode が open で blocked だけを使える")
	}
	r := core.AppRules{Mode: core.AppsOpen, Blocked: []string{}}
	if len(in.Blocked) > maxApps {
		return r, bad("windows_apps.blocked は %d 件まで", maxApps)
	}
	seen := map[string]bool{}
	for _, p := range in.Blocked {
		p = strings.TrimSpace(p)
		if !windowsPackage.MatchString(p) {
			return r, bad("windows_apps.blocked に使えないパッケージ名 %q", p)
		}
		if !seen[p] {
			seen[p] = true
			r.Blocked = append(r.Blocked, p)
		}
	}
	return r, nil
}

func (in appRulesJSON) toRules() (core.AppRules, error) {
	return in.toAppRules("android_apps", androidPackage)
}

// toAppleRules は iPhone・Mac のアプリのルール。入れさせる（required）はまだ使えない。
func (in appRulesJSON) toAppleRules() (core.AppRules, error) {
	if len(in.Required) > 0 {
		return core.AppRules{}, bad("apple_apps.required は、いまは使えない（アプリを入れる仕組みはまだ無い）")
	}
	return in.toAppRules("apple_apps", appleBundleID)
}

func (in appRulesJSON) toAppRules(name string, valid *regexp.Regexp) (core.AppRules, error) {
	r := core.AppRules{Mode: in.Mode}
	if r.Mode == "" {
		r.Mode = core.AppsOpen
	}
	if r.Mode != core.AppsOpen && r.Mode != core.AppsAllowlist {
		return r, bad("%s.mode は open か allowlist", name)
	}
	seen := map[string]string{}
	check := func(field string, in []string) ([]string, error) {
		if len(in) > maxApps {
			return nil, bad("%s.%s は %d 件まで", name, field, maxApps)
		}
		out := []string{}
		for _, p := range in {
			p = strings.TrimSpace(p)
			if len(p) > 255 || !valid.MatchString(p) {
				return nil, bad("%s.%s に使えない名前 %q", name, field, p)
			}
			if f, ok := seen[p]; ok {
				if f == field {
					continue
				}
				return nil, bad("%q が %s の %s と %s の両方にある", p, name, f, field)
			}
			seen[p] = field
			out = append(out, p)
		}
		return out, nil
	}
	var err error
	if r.Required, err = check("required", in.Required); err != nil {
		return r, err
	}
	if r.Allowed, err = check("allowed", in.Allowed); err != nil {
		return r, err
	}
	if r.Blocked, err = check("blocked", in.Blocked); err != nil {
		return r, err
	}
	return r, nil
}

func normalizeDomains(field string, in []string) ([]string, error) {
	if len(in) > maxPolicyDomains {
		return nil, bad("%s は %d 件まで", field, maxPolicyDomains)
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		n := filter.Normalize(strings.TrimPrefix(strings.TrimSpace(d), "*."))
		if n == "" {
			return nil, bad("%s に使えないドメイン %q", field, d)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func (in policyInput) toPolicy(id string) (core.Policy, error) {
	p := core.Policy{ID: id, OrgID: in.OrgID, Name: strings.TrimSpace(in.Name), Mode: in.Mode, TimeZone: in.TimeZone, LogQueries: in.LogQueries, ListIDs: in.Blocklists}
	if p.Name == "" || len(p.Name) > 100 {
		return p, bad("name は 1〜100 文字")
	}
	if p.Mode == "" {
		p.Mode = core.FilterBlocklist
	}
	if p.Mode != core.FilterBlocklist && p.Mode != core.FilterAllowlistOnly {
		return p, bad("mode は blocklist か allowlist_only")
	}
	if p.TimeZone != "" {
		if _, err := time.LoadLocation(p.TimeZone); err != nil {
			return p, bad("time_zone が分からない（%q）", p.TimeZone)
		}
	}
	if in.Device.PasscodeMinLength < 0 || in.Device.PasscodeMinLength > 16 {
		return p, bad("device.passcode_min_length は 0〜16")
	}
	p.Device = core.DeviceRules(in.Device)
	var err error
	if p.AndroidApps, err = in.Android.toRules(); err != nil {
		return p, err
	}
	if p.WindowsApps, err = in.Windows.toWindowsRules(); err != nil {
		return p, err
	}
	if p.AppleApps, err = in.Apple.toAppleRules(); err != nil {
		return p, err
	}
	if p.Compliance, err = in.Compliance.toRules(); err != nil {
		return p, err
	}
	if p.WiFi, err = toWiFi(in.WiFi); err != nil {
		return p, err
	}
	if p.Allow, err = normalizeDomains("allow", in.Allow); err != nil {
		return p, err
	}
	if p.Block, err = normalizeDomains("block", in.Block); err != nil {
		return p, err
	}
	if len(in.QuietHours) > 50 {
		return p, bad("quiet_hours は 50 件まで")
	}
	for _, wj := range in.QuietHours {
		var w core.Window
		if w.Start, err = parseClock(wj.Start); err != nil {
			return p, err
		}
		if w.End, err = parseClock(wj.End); err != nil {
			return p, err
		}
		if w.End == 24*60 {
			w.End = 0
		}
		if w.Start == 24*60 {
			return p, bad("start に 24:00 は使えない")
		}
		if w.Start == w.End {
			return p, bad("start と end が同じ")
		}
		for _, d := range wj.Days {
			i := indexOf(dayNames, strings.ToLower(d))
			if i < 0 {
				return p, bad("days は sun〜sat（%q）", d)
			}
			w.Days = append(w.Days, time.Weekday(i))
		}
		p.Quiet = append(p.Quiet, w)
	}
	return p, nil
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// --- blocklists

type blocklistJSON struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Domains     int        `json:"domains"`
	RefreshedAt *time.Time `json:"refreshed_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func toBlocklistJSON(b core.Blocklist) blocklistJSON {
	return blocklistJSON{b.ID, b.Name, b.URL, b.Domains, optTime(b.RefreshedAt), b.LastError}
}

// --- orgs, groups, admins

type orgJSON struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Kind            core.OrgKind `json:"kind"`
	DefaultPolicyID string       `json:"default_policy_id,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
}

func toOrgJSON(o core.Org) orgJSON {
	return orgJSON{o.ID, o.Name, o.Kind, o.DefaultPolicyID, o.CreatedAt}
}

type orgInput struct {
	Name            *string       `json:"name"`
	Kind            *core.OrgKind `json:"kind"`
	DefaultPolicyID *string       `json:"default_policy_id"`
}

func (in orgInput) apply(o *core.Org) error {
	if in.Name != nil {
		o.Name = strings.TrimSpace(*in.Name)
	}
	if in.Kind != nil {
		o.Kind = *in.Kind
	}
	if in.DefaultPolicyID != nil {
		o.DefaultPolicyID = *in.DefaultPolicyID
	}
	if o.Name == "" || len(o.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if o.Kind != core.OrgFamily && o.Kind != core.OrgCompany {
		return bad("kind は family か company")
	}
	return nil
}

type groupJSON struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	PolicyID  string    `json:"policy_id,omitempty"`
	Priority  int       `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
}

func toGroupJSON(g core.Group) groupJSON {
	return groupJSON{g.ID, g.OrgID, g.Name, g.PolicyID, g.Priority, g.CreatedAt}
}

type groupInput struct {
	OrgID    *string `json:"org_id"` // 作るときだけ
	Name     *string `json:"name"`
	PolicyID *string `json:"policy_id"`
	Priority *int    `json:"priority"`
}

func (in groupInput) apply(g *core.Group) error {
	if in.Name != nil {
		g.Name = strings.TrimSpace(*in.Name)
	}
	if in.PolicyID != nil {
		g.PolicyID = *in.PolicyID
	}
	if in.Priority != nil {
		g.Priority = *in.Priority
	}
	if g.Name == "" || len(g.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if g.Priority < -1000 || g.Priority > 1000 {
		return bad("priority は -1000〜1000")
	}
	return nil
}

type bindingJSON struct {
	ID        string         `json:"id"`
	Issuer    string         `json:"issuer"`
	Subject   string         `json:"subject"`
	Label     string         `json:"label,omitempty"`
	Role      core.AdminRole `json:"role"`
	OrgID     string         `json:"org_id,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

func toBindingJSON(b core.AdminBinding) bindingJSON {
	return bindingJSON{b.ID, b.Issuer, b.Subject, b.Label, b.Role, b.OrgID, b.CreatedAt}
}
