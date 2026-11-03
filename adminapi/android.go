package adminapi

import (
	"errors"
	"net/http"
	"net/mail"
	"time"

	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/core"
)

// androidReady は Android の管理が設定されているか。無ければ 501 を返す。
func (s *Server) androidReady(w http.ResponseWriter) bool {
	if s.Android == nil {
		writeErr(w, http.StatusNotImplemented, "android_not_configured", "設定の android（Google Cloud のプロジェクトとサービスアカウントの鍵）が無い")
		return false
	}
	return true
}

func writeAndroidErr(w http.ResponseWriter, err error) {
	var api *android.APIError
	switch {
	case errors.Is(err, android.ErrNoEnterprise):
		writeErr(w, http.StatusConflict, "android_not_started", err.Error())
	case errors.Is(err, android.ErrNotManaged):
		writeErr(w, http.StatusConflict, "not_managed", err.Error())
	case errors.Is(err, core.ErrConflict):
		writeErr(w, http.StatusConflict, "conflict", err.Error())
	case errors.As(err, &api):
		// Google の側のエラー。内容は管理者が直すのに要るので返す。
		writeErr(w, http.StatusBadGateway, "android_api", api.Error())
	default:
		writeStoreErr(w, err)
	}
}

// GET /v1/orgs/{id}/android
func (s *Server) getOrgAndroid(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canRead(w, r, id) {
		return
	}
	e, err := s.Store.GetAndroidEnterprise(r.Context(), id)
	if errors.Is(err, core.ErrNotFound) {
		writeJSON(w, 200, map[string]any{"started": false})
		return
	}
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"started": true, "enterprise": e.Name, "created_at": e.CreatedAt})
}

// POST /v1/orgs/{id}/android/signup は Google の登録の画面の URL を返す。管理者がブラウザーで開く。
func (s *Server) androidSignup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AdminEmail string `json:"admin_email"`
	}
	if !readJSON(w, r, &in) || !s.androidReady(w) {
		return
	}
	id := r.PathValue("id")
	if !canWrite(w, r, id) {
		return
	}
	if _, err := s.Store.GetOrg(r.Context(), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	if in.AdminEmail != "" {
		if a, err := mail.ParseAddress(in.AdminEmail); err != nil || a.Address != in.AdminEmail {
			writeErr(w, 400, "invalid_request", "admin_email がメールアドレスではない")
			return
		}
	}
	u, err := s.Android.StartSignup(r.Context(), id, in.AdminEmail)
	if err != nil {
		writeAndroidErr(w, err)
		return
	}
	s.audit(r, id, "android.signup", id)
	writeJSON(w, 200, map[string]any{"url": u, "expires_in": 3600})
}

type managedJSON struct {
	Provider        string            `json:"provider"`
	State           core.ManagedState `json:"state"`
	Mode            string            `json:"mode,omitempty"`
	Model           string            `json:"model,omitempty"`
	OSVersion       string            `json:"os_version,omitempty"`
	SecurityPatch   string            `json:"security_patch,omitempty"`
	PolicyCompliant bool              `json:"policy_compliant"`
	Problems        []string          `json:"problems"`
	Encrypted       bool              `json:"encrypted"`
	ScreenLock      bool              `json:"screen_lock"`
	EnrolledAt      *time.Time        `json:"enrolled_at,omitempty"`
	ReportedAt      *time.Time        `json:"reported_at,omitempty"`
}

func toManagedJSON(m core.Managed) managedJSON {
	return managedJSON{m.Provider, m.State, m.Mode, m.Model, m.OSVersion, m.SecurityPatch, m.PolicyCompliant,
		nonNil(m.Problems), m.Encrypted, m.ScreenLock, optTime(m.EnrolledAt), optTime(m.ReportedAt)}
}

// isManaged は端末が MDM の管理の下にあるか（消したり OS を変えたりする前に見る）。
func (s *Server) isManaged(r *http.Request, id string) (bool, error) {
	m, err := s.Store.GetManaged(r.Context(), id)
	if errors.Is(err, core.ErrNotFound) {
		return false, nil
	}
	return err == nil && m.State != core.ManagedRemoved, err
}
