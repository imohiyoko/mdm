package apple

import (
	"bytes"
	"testing"

	"howett.net/plist"

	"github.com/imohiyoko/mdm/core"
)

func decodeProfile(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var p struct{ PayloadContent []map[string]any }
	if _, err := plist.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p.PayloadContent
}

func TestSafariRestrictions(t *testing.T) {
	pol := core.Policy{Safari: core.SafariRules{Disabled: true, PopupsBlocked: true, FraudWarningForced: true,
		AutoFillDisabled: true, PrivateBrowsingDisabled: true, CookiesBlocked: true}}
	r := decodeProfile(t, policyProfile("d", pol, true, true))[0]
	// キーと型は Apple の com.apple.applicationaccess.yaml に合わせる。
	want := map[string]any{"allowSafari": false, "safariAllowPopups": false, "safariForceFraudWarning": true,
		"safariAllowAutoFill": false, "allowSafariPrivateBrowsing": false, "safariAcceptCookies": 0.0}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r[k], v)
		}
	}
	// 何も止めなければ Safari のキーは書かない（今のポリシーの形を変えず、配り直しを起こさない）。
	r = decodeProfile(t, policyProfile("d", core.Policy{}, true, true))[0]
	for k := range want {
		if _, ok := r[k]; ok {
			t.Errorf("%s written without a rule", k)
		}
	}
}

func TestWebFilterOnlySupervisedIOS(t *testing.T) {
	pol := core.Policy{WebFilter: core.WebFilterRules{LimitAdult: true, Permitted: []string{"https://ok.example/"}, Denied: []string{"https://bad.example/"}}}
	for _, c := range []struct {
		supervised, ios bool
		want            bool
	}{{true, true, true}, {false, true, false}, {true, false, false}} {
		pl := decodeProfile(t, policyProfile("d", pol, c.supervised, c.ios))
		if got := len(pl) == 2; got != c.want {
			t.Errorf("supervised=%v ios=%v: web filter %v", c.supervised, c.ios, got)
		}
	}
	f := decodeProfile(t, policyProfile("d", pol, true, true))[1]
	if f["PayloadType"] != "com.apple.webcontent-filter" || f["FilterType"] != "BuiltIn" || f["AutoFilterEnabled"] != true ||
		f["PermittedURLs"].([]any)[0] != "https://ok.example/" || f["DenyListURLs"].([]any)[0] != "https://bad.example/" {
		t.Fatal(f)
	}
	if _, ok := f["AllowListBookmarks"]; ok {
		t.Fatal(f)
	}
}

func TestWebFilterAllowOnly(t *testing.T) {
	pol := core.Policy{WebFilter: core.WebFilterRules{Denied: []string{"https://bad.example/"},
		AllowOnly: []core.WebFilterBookmark{{URL: "https://school.example/", Title: "学校"}}}}
	f := decodeProfile(t, policyProfile("d", pol, true, true))[1]
	bm := f["AllowListBookmarks"].([]any)[0].(map[string]any)
	if bm["URL"] != "https://school.example/" || bm["Title"] != "学校" {
		t.Fatal(f)
	}
	for _, k := range []string{"AutoFilterEnabled", "DenyListURLs", "PermittedURLs"} {
		if _, ok := f[k]; ok {
			t.Errorf("%s with AllowListBookmarks", k)
		}
	}
	// 監視モードと分かると中身が変わる（配り直す）。
	if bytes.Equal(policyProfile("d", pol, true, true), policyProfile("d", pol, false, true)) {
		t.Fatal("same profile")
	}
}
