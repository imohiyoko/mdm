package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/mdm/android"
	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/windows"
)

// 端末の登録・命令・管理を外す。機種ごとの管理の仕組みに振り分ける。

func (s *Server) windowsReady(w http.ResponseWriter) bool {
	if s.Windows == nil {
		writeErr(w, http.StatusNotImplemented, "windows_not_configured", "設定の windows（端末から届く入り口と証明書）が無い")
		return false
	}
	return true
}

// POST /v1/devices/{id}/enroll は登録の情報を作る。Android は QR コード・リンク、Windows は合言葉。
func (s *Server) enrollDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode       string `json:"mode"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.TTLMinutes < 0 || in.TTLMinutes > 30*24*60 {
		writeErr(w, 400, "invalid_request", "ttl_minutes は 1〜43200")
		return
	}
	ttl := time.Duration(in.TTLMinutes) * time.Minute
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	switch d.Platform {
	case core.PlatformAndroid:
		s.enrollAndroid(w, r, d, in.Mode, ttl)
	case core.PlatformWindows:
		if in.Mode != "" {
			writeErr(w, 400, "invalid_request", "Windows に mode は無い")
			return
		}
		if !s.windowsReady(w) {
			return
		}
		e, err := s.Windows.CreateEnrollment(r.Context(), d, ttl)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		s.audit(r, d.OrgID, "device.enroll", d.ID)
		writeJSON(w, 200, map[string]any{"enrollment": e})
	default:
		writeErr(w, 400, "invalid_request", "登録できるのはいまは Android と Windows の端末だけ")
	}
}

func (s *Server) enrollAndroid(w http.ResponseWriter, r *http.Request, d core.Device, mode string, ttl time.Duration) {
	if mode != "" && mode != android.ModeFullyManaged && mode != android.ModeWorkProfile {
		writeErr(w, 400, "invalid_request", "mode は fully_managed か work_profile")
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
	e, err := s.Android.Enroll(r.Context(), d, label, android.EnrollOptions{Mode: mode, TTL: ttl})
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

// provider は端末を管理している仕組み（"android"・"windows"）。管理していなければ空。
func (s *Server) provider(w http.ResponseWriter, r *http.Request, d core.Device) (core.Managed, bool) {
	m, err := s.Store.GetManaged(r.Context(), d.ID)
	if errors.Is(err, core.ErrNotFound) {
		writeErr(w, http.StatusConflict, "not_managed", "端末は管理の下に無い（先に登録する）")
		return m, false
	}
	if err != nil {
		writeStoreErr(w, err)
		return m, false
	}
	switch m.Provider {
	case android.Provider:
		return m, s.androidReady(w)
	case windows.Provider:
		return m, s.windowsReady(w)
	}
	writeErr(w, http.StatusConflict, "not_managed", "")
	return m, false
}

// POST /v1/devices/{id}/commands は端末に命令を送る。
//   - lock（Android）・reboot（Android・Windows）・wipe（Windows。confirm_wipe が要る）
func (s *Server) deviceCommand(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type        string `json:"type"`
		ConfirmWipe bool   `json:"confirm_wipe"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	d, ok := s.loadDevice(w, r, true)
	if !ok {
		return
	}
	m, ok := s.provider(w, r, d)
	if !ok {
		return
	}
	var err error
	switch {
	case m.Provider == android.Provider && (in.Type == android.CommandLock || in.Type == android.CommandReboot):
		err = s.Android.Command(r.Context(), d, in.Type)
	case m.Provider == windows.Provider && (in.Type == windows.CommandReboot || in.Type == windows.CommandWipe):
		if in.Type == windows.CommandWipe && !in.ConfirmWipe {
			writeErr(w, 400, "confirm_wipe_required", "初期化すると端末のデータが消える。よければ confirm_wipe を true にする")
			return
		}
		err = s.Windows.Command(r.Context(), d, in.Type)
	default:
		writeErr(w, 400, "invalid_request", "この端末で使える type は、Android が lock・reboot、Windows が reboot・wipe")
		return
	}
	if errors.Is(err, windows.ErrNotManaged) {
		writeErr(w, http.StatusConflict, "not_managed", err.Error())
		return
	}
	if err != nil {
		writeAndroidErr(w, err)
		return
	}
	s.audit(r, d.OrgID, "device.command."+in.Type, d.ID)
	w.WriteHeader(http.StatusAccepted)
}

// GET /v1/devices/{id}/commands は端末に送った命令（Windows）の最近の記録。
func (s *Server) listCommands(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadDevice(w, r, false)
	if !ok {
		return
	}
	cs, err := s.Store.ListCommands(r.Context(), d.ID, 100)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	type c struct {
		ID        int64     `json:"id"`
		Verb      string    `json:"verb"`
		LocURI    string    `json:"loc_uri"`
		Purpose   string    `json:"purpose"`
		State     string    `json:"state"`
		Status    string    `json:"status,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := []c{}
	for _, x := range cs {
		out = append(out, c{x.ID, x.Verb, x.LocURI, x.Purpose, string(x.State), x.Status, x.CreatedAt})
	}
	writeJSON(w, 200, map[string]any{"commands": out})
}

// POST /v1/devices/{id}/unenroll は端末を管理から外す。
//   - Android：完全管理の端末は初期化されるので confirm_wipe が要る
//   - Windows：端末が次に通信してきたときに外れる（202）。force なら待たずに MDM の側だけ外す
func (s *Server) unenrollDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfirmWipe bool   `json:"confirm_wipe"`
		Force       bool   `json:"force"`
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
	if !ok {
		return
	}
	m, ok := s.provider(w, r, d)
	if !ok {
		return
	}
	switch m.Provider {
	case android.Provider:
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
	case windows.Provider:
		if err := s.Windows.Unenroll(r.Context(), d, in.Force); err != nil {
			writeStoreErr(w, err)
			return
		}
		s.audit(r, d.OrgID, "device.unenroll", d.ID)
		if _, err := s.Store.GetManaged(r.Context(), d.ID); errors.Is(err, core.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}
