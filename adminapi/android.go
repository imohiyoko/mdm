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

// POST /v1/devices/{id}/enroll は Android の端末の登録の QR コード（とリンク）を作る。
func (s *Server) enrollDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode       string `json:"mode"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Mode != "" && in.Mode != android.ModeFullyManaged && in.Mode != android.ModeWorkProfile {
		writeErr(w, 400, "invalid_request", "mode は fully_managed か work_profile")
		return
	}
	if in.TTLMinutes < 0 || in.TTLMinutes > 30*24*60 {
		writeErr(w, 400, "invalid_request", "ttl_minutes は 1〜43200")
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	if d.Platform != core.PlatformAndroid {
		writeErr(w, 400, "invalid_request", "登録できるのはいまは Android の端末だけ")
		return
	}
	if !s.androidReady(w) {
		return
	}
	// 端末に固定する DoT のホスト名を新しくする。平文はサーバーに残さず、AMAPI のポリシーにだけ書く。
	label, labelHash := core.NewFilterToken()
	prev := d.DoTLabelHash
	d.DoTLabelHash = labelHash
	if err := s.Store.UpdateDevice(r.Context(), d); err != nil {
		writeStoreErr(w, err)
		return
	}
	e, err := s.Android.Enroll(r.Context(), d, label, android.EnrollOptions{Mode: in.Mode, TTL: time.Duration(in.TTLMinutes) * time.Minute})
	if err != nil {
		d.DoTLabelHash = prev
		if err2 := s.Store.UpdateDevice(r.Context(), d); err2 != nil && s.Logger != nil {
			s.Logger.Error("restore dot label", "err", err2)
		}
		writeAndroidErr(w, err)
		return
	}
	s.changed(r, d.OrgID, "device.enroll", d.ID)
	writeJSON(w, 200, map[string]any{"enrollment": e})
}

// POST /v1/devices/{id}/commands は端末に命令を送る（lock・reboot）。
func (s *Server) deviceCommand(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type string `json:"type"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Type != android.CommandLock && in.Type != android.CommandReboot {
		writeErr(w, 400, "invalid_request", "type は lock か reboot")
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok || !s.androidReady(w) {
		return
	}
	if err := s.Android.Command(r.Context(), d, in.Type); err != nil {
		writeAndroidErr(w, err)
		return
	}
	s.audit(r, d.OrgID, "device.command."+in.Type, d.ID)
	w.WriteHeader(http.StatusAccepted)
}

// POST /v1/devices/{id}/unenroll は端末を管理から外す。完全管理の端末は初期化されるので confirm_wipe が要る。
func (s *Server) unenrollDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfirmWipe bool   `json:"confirm_wipe"`
		Reason      string `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Reason) > 200 {
		writeErr(w, 400, "invalid_request", "reason は 200 バイトまで")
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok || !s.androidReady(w) {
		return
	}
	m, found, err := s.Android.Managed(r.Context(), d)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if !found {
		writeAndroidErr(w, android.ErrNotManaged)
		return
	}
	if m.ExternalID != "" && m.State != core.ManagedRemoved && m.Mode == android.ModeFullyManaged && !in.ConfirmWipe {
		writeErr(w, 400, "confirm_wipe_required", "完全管理の端末は管理を外すと初期化される。よければ confirm_wipe を true にする")
		return
	}
	if err := s.Android.Unenroll(r.Context(), d, in.Reason); err != nil {
		writeAndroidErr(w, err)
		return
	}
	s.audit(r, d.OrgID, "device.unenroll", d.ID)
	w.WriteHeader(http.StatusNoContent)
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
