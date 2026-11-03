package adminapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/adminapi"
	"github.com/imohiyoko/mdm/blocklist"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/internal/testkit"
)

const secret = "mdm_test-secret"

type client struct {
	t   *testing.T
	srv *httptest.Server
}

func (c client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, &buf)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func newServer(t *testing.T) (client, core.Store, *testkit.Clock) {
	t.Helper()
	store := testkit.Store(t)
	clock := testkit.NewClock(time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC))
	if err := store.CreatePolicy(context.Background(), core.Policy{ID: filter.DefaultPolicyID, Name: "既定", Mode: core.FilterBlocklist}); err != nil {
		t.Fatal(err)
	}
	engine := &filter.Engine{Store: store, Clock: clock}
	sum := sha256.Sum256([]byte(secret))
	s := &adminapi.Server{
		Store: store, Clock: clock, Engine: engine,
		Refresher: &blocklist.Refresher{Store: store, Clock: clock, OnChange: engine.Invalidate},
		Tokens:    []adminapi.AdminToken{{Name: "parent", SHA256: hex.EncodeToString(sum[:])}},
		Endpoints: adminapi.FilterEndpoints{DoHBaseURL: "https://dns.example", DoTDomain: "dns.example"},
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return client{t, srv}, store, clock
}

func TestAuth(t *testing.T) {
	c, _, _ := newServer(t)
	for _, h := range []string{"", "Bearer wrong", "Basic " + secret} {
		req, _ := http.NewRequest("GET", c.srv.URL+"/v1/devices", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%q: %d", h, resp.StatusCode)
		}
	}
	resp, _ := http.Get(c.srv.URL + "/healthz")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz: %d", resp.StatusCode)
	}
}

func TestFamilyFlow(t *testing.T) {
	c, store, clock := newServer(t)

	var pol map[string]any
	if code := c.do("POST", "/v1/policies", map[string]any{
		"name": "小学生", "block": []string{"*.game.example"}, "allow": []string{"school.example"},
		"quiet_hours": []map[string]any{{"start": "21:00", "end": "07:00"}}, "time_zone": "Asia/Tokyo",
	}, &pol); code != 201 {
		t.Fatalf("policy: %d %v", code, pol)
	}
	polID := pol["id"].(string)
	if pol["block"].([]any)[0] != "game.example" || pol["mode"] != "blocklist" {
		t.Fatalf("正規化: %v", pol)
	}

	var person map[string]any
	if code := c.do("POST", "/v1/people", map[string]any{"name": "たろう", "policy_id": polID}, &person); code != 201 {
		t.Fatalf("person: %d %v", code, person)
	}
	if person["role"] != "child" {
		t.Fatalf("既定は子ども: %v", person)
	}

	var created struct {
		Device map[string]any
		Filter map[string]string
	}
	if code := c.do("POST", "/v1/devices", map[string]any{"name": "たろうの Android", "platform": "android", "person_id": person["id"]}, &created); code != 201 {
		t.Fatalf("device: %d", code)
	}
	tok := created.Filter["token"]
	if !core.LooksLikeFilterToken(tok) || created.Filter["doh_url"] != "https://dns.example/dns-query/"+tok ||
		created.Filter["dot_hostname"] != tok+".dns.example" || !strings.HasSuffix(created.Filter["apple_profile_url"], tok+".mobileconfig") {
		t.Fatalf("filter setup: %v", created.Filter)
	}
	devID := created.Device["id"].(string)

	check := func(name string) map[string]any {
		var out map[string]any
		if code := c.do("POST", "/v1/devices/"+devID+"/check", map[string]any{"name": name}, &out); code != 200 {
			t.Fatalf("check: %d", code)
		}
		return out
	}
	if r := check("www.game.example"); r["action"] != "block" || r["policy_id"] != polID {
		t.Fatalf("持ち主のポリシー: %v", r)
	}

	// 今すぐ止める・戻す。
	if code := c.do("POST", "/v1/devices/"+devID+"/pause", map[string]any{"minutes": 30}, nil); code != 200 {
		t.Fatalf("pause: %d", code)
	}
	if r := check("news.example"); r["reason"] != "paused" {
		t.Fatalf("止めた: %v", r)
	}
	c.do("DELETE", "/v1/devices/"+devID+"/pause", nil, nil)
	if r := check("news.example"); r["action"] != "allow" {
		t.Fatalf("戻した: %v", r)
	}

	// 夜（22:00 JST）。
	clock.Set(time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC))
	if r := check("news.example"); r["reason"] != "quiet_hours" {
		t.Fatalf("夜: %v", r)
	}

	// 秘密の作り直し。古い秘密は効かない。
	var rotated struct{ Filter map[string]string }
	c.do("POST", "/v1/devices/"+devID+"/filter-token", nil, &rotated)
	if rotated.Filter["token"] == tok || !core.LooksLikeFilterToken(rotated.Filter["token"]) {
		t.Fatal("作り直し")
	}
	if _, err := store.GetDeviceByTokenHash(context.Background(), core.HashFilterToken(tok)); err != core.ErrNotFound {
		t.Fatal("古い秘密が残っている")
	}

	// 使われているものは消せない。既定のポリシーも消せない。
	if code := c.do("DELETE", "/v1/policies/"+polID, nil, nil); code != 409 {
		t.Fatalf("使用中のポリシー: %d", code)
	}
	if code := c.do("DELETE", "/v1/policies/default", nil, nil); code != 409 {
		t.Fatalf("既定のポリシー: %d", code)
	}
	if code := c.do("DELETE", "/v1/people/"+person["id"].(string), nil, nil); code != 409 {
		t.Fatalf("端末のある人: %d", code)
	}

	var audit struct{ Events []map[string]any }
	c.do("GET", "/v1/audit", nil, &audit)
	if len(audit.Events) < 6 || audit.Events[0]["actor"] != "parent" {
		t.Fatalf("操作の記録: %v", audit.Events)
	}
}

func TestValidation(t *testing.T) {
	c, _, _ := newServer(t)
	for _, body := range []map[string]any{
		{"name": ""},
		{"name": "x", "mode": "everything"},
		{"name": "x", "block": []string{"not a domain"}},
		{"name": "x", "time_zone": "Mars/Base"},
		{"name": "x", "quiet_hours": []map[string]any{{"start": "25:00", "end": "07:00"}}},
		{"name": "x", "quiet_hours": []map[string]any{{"start": "07:00", "end": "07:00"}}},
		{"name": "x", "quiet_hours": []map[string]any{{"days": []string{"funday"}, "start": "07:00", "end": "08:00"}}},
		{"name": "x", "blocklists": []string{"bl_missing"}},
		{"name": "x", "unknown_field": true},
	} {
		if code := c.do("POST", "/v1/policies", body, nil); code != 400 {
			t.Errorf("%v: %d", body, code)
		}
	}
	if code := c.do("POST", "/v1/devices", map[string]any{"name": "x", "platform": "blackberry"}, nil); code != 400 {
		t.Errorf("platform: %d", code)
	}
	if code := c.do("POST", "/v1/blocklists", map[string]any{"name": "x", "url": "http://insecure.example/list"}, nil); code != 400 {
		t.Errorf("blocklist http: %d", code)
	}
	if code := c.do("GET", "/v1/devices/dev_missing", nil, nil); code != 404 {
		t.Errorf("missing device: %d", code)
	}
}
