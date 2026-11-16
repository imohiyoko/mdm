package adminapi_test

import (
	"strings"
	"testing"

	"github.com/imohiyoko/mdm/internal/testkit"
)

func TestPolicySafariAndWebFilter(t *testing.T) {
	c, _, _ := newServer(t)
	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "子ども",
		"safari":     map[string]any{"popups_blocked": true, "private_browsing_disabled": true},
		"web_filter": map[string]any{"limit_adult": true, "permitted": []string{"https://ok.example/"}, "denied": []string{" https://bad.example/x ", "https://bad.example/x"}},
	}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	var got map[string]any
	if code := c.do("GET", "/v1/policies/"+pol["id"].(string), nil, &got); code != 200 {
		t.Fatal(code)
	}
	sf := got["safari"].(map[string]any)
	wf := got["web_filter"].(map[string]any)
	if sf["popups_blocked"] != true || sf["private_browsing_disabled"] != true || sf["disabled"] != false ||
		wf["limit_adult"] != true || len(wf["denied"].([]any)) != 1 || wf["denied"].([]any)[0] != "https://bad.example/x" {
		t.Fatal(got)
	}
	// 許可した URL だけ。title が無ければ URL を使う。
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "学校",
		"web_filter": map[string]any{"allow_only": []map[string]any{{"url": "https://school.example/"}}}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if b := pol["web_filter"].(map[string]any)["allow_only"].([]any)[0].(map[string]any); b["title"] != "https://school.example/" {
		t.Fatal(b)
	}
	// 題を省いた長い URL は、題だけ切って受け付ける。
	long := "https://school.example/" + strings.Repeat("a", 200)
	if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "長い",
		"web_filter": map[string]any{"allow_only": []map[string]any{{"url": long}}}}, &pol); code != 201 {
		t.Fatal(code, pol)
	}
	if b := pol["web_filter"].(map[string]any)["allow_only"].([]any)[0].(map[string]any); b["url"] != long || len([]rune(b["title"].(string))) != 100 {
		t.Fatal(b)
	}
	many := make([]string, 501)
	for i := range many {
		many[i] = "https://x.example/" + strings.Repeat("a", i%5) + string(rune('a'+i%26))
	}
	for _, bad := range []map[string]any{
		{"denied": []string{"javascript:alert(1)"}},
		{"denied": []string{"ftp://x.example/"}},
		{"denied": []string{"https://user:pw@x.example/"}},
		{"denied": []string{"https://x.example/a b"}},
		{"denied": many},
		{"permitted": []string{"https://ok.example/"}}, // limit_adult が無い
		{"limit_adult": true, "allow_only": []map[string]any{{"url": "https://a.example/"}}},
		{"allow_only": []map[string]any{{"url": "https://a.example/", "title": strings.Repeat("あ", 101)}}},
	} {
		if code := c.do("POST", "/v1/policies", map[string]any{"org_id": testkit.OrgID, "name": "x", "web_filter": bad}, nil); code != 400 {
			t.Fatal(bad, code)
		}
	}
}
