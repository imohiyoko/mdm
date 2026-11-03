// Package androidtest は Android Management API の偽物（テスト用）。
package androidtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/imohiyoko/mdm/android"
)

// EnterpriseToken は偽物が受け付ける enterpriseToken。
const EnterpriseToken = "ent-token"

// Fake は AMAPI の偽物。使う機能の分だけを持つ。
type Fake struct {
	mu          sync.Mutex
	Enterprise  string                    // 作る enterprise の名前
	CallbackURL string                    // 最後に作った登録の画面の戻り先
	Policies    map[string]map[string]any // 名前 → ポリシー
	Masks       map[string][]string       // 名前 → 最後の updateMask
	Patches     int
	Tokens      []android.EnrollmentToken
	Devices     []android.Device
	Commands    []string // "端末の名前 種類"
	Deleted     []string // 消した端末とポリシー
	// Fail が空でなければ、その道（"PATCH policies" など）で 500 を返す。
	Fail string
}

// New は偽物を起動し、それにつながる Client を返す。
func New(t testing.TB) (*Fake, *android.Client) {
	f := &Fake{Enterprise: "enterprises/LC0test", Policies: map[string]map[string]any{}, Masks: map[string][]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &android.Client{BaseURL: srv.URL + "/v1/", HTTP: srv.Client()}
}

// Policy は名前のポリシー（無ければ nil）。
func (f *Fake) Policy(name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Policies[name]
}

// SetDevices は端末の一覧を入れ替える。
func (f *Fake) SetDevices(ds ...android.Device) {
	f.mu.Lock()
	f.Devices = ds
	f.mu.Unlock()
}

func fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "status": code, "message": code}})
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	q := r.URL.Query()
	kind := r.Method + " " + kindOf(path)
	if f.Fail != "" && f.Fail == kind {
		fail(w, 500, "INTERNAL")
		return
	}
	switch {
	case kind == "POST signupUrls":
		f.CallbackURL = q.Get("callbackUrl")
		_ = json.NewEncoder(w).Encode(android.SignupURL{Name: "signupUrls/C1", URL: "https://play.google.com/work/adminsignup?token=x"})
	case kind == "POST enterprises":
		if q.Get("enterpriseToken") != EnterpriseToken || q.Get("signupUrlName") != "signupUrls/C1" || q.Get("projectId") == "" {
			fail(w, 400, "INVALID_ARGUMENT")
			return
		}
		_ = json.NewEncoder(w).Encode(android.Enterprise{Name: f.Enterprise})
	case kind == "PATCH policies":
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, 400, "INVALID_ARGUMENT")
			return
		}
		f.Patches++
		mask := q.Get("updateMask")
		cur := f.Policies[path]
		if mask == "" || cur == nil {
			f.Policies[path] = body
			f.Masks[path] = nil
		} else {
			f.Masks[path] = strings.Split(mask, ",")
			for _, field := range f.Masks[path] {
				applyField(cur, body, strings.Split(field, "."))
			}
		}
		_ = json.NewEncoder(w).Encode(f.Policies[path])
	case kind == "DELETE policies":
		if _, ok := f.Policies[path]; !ok {
			fail(w, 404, "NOT_FOUND")
			return
		}
		delete(f.Policies, path)
		f.Deleted = append(f.Deleted, path)
		_, _ = w.Write([]byte("{}"))
	case kind == "POST enrollmentTokens":
		var t android.EnrollmentToken
		_ = json.NewDecoder(r.Body).Decode(&t)
		if _, ok := f.Policies[t.PolicyName]; !ok {
			fail(w, 400, "INVALID_ARGUMENT")
			return
		}
		t.Name = fmt.Sprintf("%s/%d", path, len(f.Tokens)+1)
		t.Value = fmt.Sprintf("TOKEN%d", len(f.Tokens)+1)
		t.QRCode = `{"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE":{"com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN":"` + t.Value + `"}}`
		f.Tokens = append(f.Tokens, t)
		_ = json.NewEncoder(w).Encode(t)
	case kind == "GET devices":
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": f.Devices})
	case kind == "POST issueCommand":
		var c android.Command
		_ = json.NewDecoder(r.Body).Decode(&c)
		f.Commands = append(f.Commands, strings.TrimSuffix(path, ":issueCommand")+" "+c.Type)
		_, _ = w.Write([]byte(`{"name":"op"}`))
	case kind == "DELETE devices":
		for i, d := range f.Devices {
			if d.Name == path {
				f.Devices = append(f.Devices[:i], f.Devices[i+1:]...)
				f.Deleted = append(f.Deleted, path)
				_, _ = w.Write([]byte("{}"))
				return
			}
		}
		fail(w, 404, "NOT_FOUND")
	default:
		fail(w, 404, "NOT_FOUND")
	}
}

// kindOf は道の種類（"policies" など）。
func kindOf(path string) string {
	if strings.HasSuffix(path, ":issueCommand") {
		return "issueCommand"
	}
	parts := strings.Split(path, "/")
	switch {
	case len(parts) == 1:
		return parts[0]
	case len(parts) >= 3:
		return parts[2]
	}
	return path
}

func applyField(dst, src map[string]any, field []string) {
	if len(field) == 1 {
		if v, ok := src[field[0]]; ok {
			dst[field[0]] = v
		} else {
			delete(dst, field[0])
		}
		return
	}
	sub, _ := src[field[0]].(map[string]any)
	if sub == nil {
		sub = map[string]any{}
	}
	d, _ := dst[field[0]].(map[string]any)
	if d == nil {
		d = map[string]any{}
		dst[field[0]] = d
	}
	applyField(d, sub, field[1:])
}
