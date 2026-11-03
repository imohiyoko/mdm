// Package windows は Windows 標準の MDM（登録は MS-MDE2、管理は OMA-DM）で Windows の端末を管理する。
//
// 登録：管理者が端末ごとに 1 回だけの合言葉を作り、利用者が Windows の「職場または学校にアクセスする」→
// 「デバイス管理のみに登録する」で、サーバーのアドレスと合言葉（パスワード）を入れる。サーバーは端末の
// 証明書を発行し、以後の管理の通信はその証明書（TLS のクライアント証明書）で端末を確かめる。
//
// 管理：端末は決まった間隔でサーバーに通信してくる（プッシュはまだ使わない）。そのときに、待ち行列の
// 命令（設定・問い合わせ・再起動など）を渡し、答えを受け取る。
package windows

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// Provider は core.Managed の Provider の値。
const Provider = "windows"

// ModeMDMOnly は「デバイス管理のみ」の登録。
const ModeMDMOnly = "mdm_only"

// 道。
const (
	PathDiscovery  = "/EnrollmentServer/Discovery.svc"
	PathPolicy     = "/EnrollmentServer/Policy.svc"
	PathEnrollment = "/EnrollmentServer/Enrollment.svc"
	PathManagement = "/ManagementServer/MDM.svc"
)

var (
	// ErrNotManaged は端末が Windows の管理の下に無い。
	ErrNotManaged = errors.New("windows: 端末は Windows の管理の下に無い")
)

// Service は Windows の管理。
type Service struct {
	Store  core.Store
	Engine *filter.Engine
	Clock  core.Clock
	CA     *CA
	// BaseURL は端末から届く https://host[:port]。登録と管理の道はこの下に置く。
	BaseURL string
	// ProviderID は端末の側での管理のサーバーの名前。空なら "imohiyoko-mdm"。
	ProviderID string
	// PollMinutes ごとに端末が通信してくる。0 なら 15。
	PollMinutes int
	// CertValidity は端末の証明書の有効期間。0 なら 5 年。
	CertValidity time.Duration
	Logger       *slog.Logger
}

func (s *Service) providerID() string {
	if s.ProviderID == "" {
		return providerIDDef
	}
	return s.ProviderID
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// --- 登録の合言葉

// Enrollment は利用者に渡す登録の情報。
type Enrollment struct {
	// Code は Windows の登録の画面でパスワードに入れる 1 回だけの合言葉。
	Code string `json:"code"`
	// Username はメールアドレスの欄に入れる値（何でもよいが、これを入れると楽）。
	Username string `json:"username"`
	// ServerURL は「サーバー」の欄に入れるアドレス。
	ServerURL string `json:"server_url"`
	// Link を Windows で開くと、メールアドレスとサーバーが入った登録の画面が開く。
	Link      string    `json:"link"`
	ExpiresAt time.Time `json:"expires_at"`
}

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 読み違えやすい文字（I・O・0・1）を除く

// newCode は 15 文字（75 ビット）の合言葉を "XXXXX-XXXXX-XXXXX" の形で作る。
func newCode() string {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(codeAlphabet[int(c)%len(codeAlphabet)]) // 32 で割り切れるので偏らない
	}
	return sb.String()
}

func hashCode(code string) []byte {
	c := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("windows-enroll:" + c))
	return sum[:]
}

// CreateEnrollment は端末 d の登録の合言葉を作る。前に作った合言葉は使えなくなる。
func (s *Service) CreateEnrollment(ctx context.Context, d core.Device, ttl time.Duration) (Enrollment, error) {
	if d.Platform != core.PlatformWindows {
		return Enrollment{}, errors.New("windows: Windows の端末ではない")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if err := s.Store.DeleteEnrollmentCodes(ctx, d.ID); err != nil {
		return Enrollment{}, err
	}
	code := newCode()
	exp := s.Clock.Now().Add(ttl)
	if err := s.Store.PutEnrollmentCode(ctx, core.EnrollmentCode{Hash: hashCode(code), DeviceID: d.ID, ExpiresAt: exp}); err != nil {
		return Enrollment{}, err
	}
	u, _ := url.Parse(s.BaseURL)
	user := "device@" + u.Hostname()
	link := "ms-device-enrollment:?" + url.Values{"mode": {"mdm"}, "username": {user}, "servername": {s.BaseURL}}.Encode()
	return Enrollment{Code: code, Username: user, ServerURL: s.BaseURL, Link: link, ExpiresAt: exp}, nil
}

// checkCode は合言葉を確かめ、端末を返す。
func (s *Service) checkCode(ctx context.Context, code string) (core.Device, error) {
	c, err := s.Store.GetEnrollmentCode(ctx, hashCode(code))
	if err != nil {
		return core.Device{}, err
	}
	if !s.Clock.Now().Before(c.ExpiresAt) {
		return core.Device{}, core.ErrNotFound
	}
	return s.Store.GetDevice(ctx, c.DeviceID)
}

// --- HTTP

// Handler は登録と管理の http.Handler。管理の道は TLS のクライアント証明書が要る。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathDiscovery, s.discovery)
	mux.HandleFunc("POST "+PathPolicy, s.policy)
	mux.HandleFunc("POST "+PathEnrollment, s.enroll)
	mux.HandleFunc("POST "+PathManagement, s.manage)
	return mux
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return b, true
}

func writeSOAP(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", soapType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Service) fault(w http.ResponseWriter, e *envelope, action, subcode, reason string) {
	relates := ""
	if e != nil {
		relates = e.Header.MessageID
	}
	writeSOAP(w, http.StatusInternalServerError, render("fault", map[string]string{
		"Action": action, "RelatesTo": relates, "Subcode": subcode, "Reason": reason,
	}))
}

func (s *Service) discovery(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Windows は最初に GET で入り口があるかを確かめる。
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	e, err := parseEnvelope(b)
	if err != nil || e.Body.Discover == nil {
		s.fault(w, e, actionDisc, "s:MessageFormat", "not a Discover request")
		return
	}
	ver := "4.0"
	if v := e.Body.Discover.Request.RequestVersion; v != "" && v < "4.0" {
		ver = v
	}
	writeSOAP(w, http.StatusOK, render("discover", map[string]string{
		"Activity": newUUID(), "RelatesTo": e.Header.MessageID, "Version": ver,
		"PolicyURL": s.BaseURL + PathPolicy, "EnrollURL": s.BaseURL + PathEnrollment,
	}))
}

func (s *Service) policy(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	e, err := parseEnvelope(b)
	if err != nil || e.Body.GetPolicies == nil {
		s.fault(w, e, actionPolicy, "s:MessageFormat", "not a GetPolicies request")
		return
	}
	if _, err := s.checkCode(r.Context(), e.Header.Security.UsernameToken.Password); err != nil {
		s.fault(w, e, actionPolicy, "s:Authentication", "the enrollment code is wrong or expired")
		return
	}
	validity := s.certValidity()
	writeSOAP(w, http.StatusOK, render("policies", map[string]any{
		"RelatesTo": e.Header.MessageID, "ValiditySeconds": int64(validity.Seconds()), "RenewalSeconds": int64(validity.Seconds() / 2),
	}))
}

func (s *Service) certValidity() time.Duration {
	if s.CertValidity == 0 {
		return 5 * 365 * 24 * time.Hour
	}
	return s.CertValidity
}

func (s *Service) enroll(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	e, err := parseEnvelope(b)
	if err != nil || e.Body.RST == nil {
		s.fault(w, e, actionEnroll, "s:MessageFormat", "not a RequestSecurityToken request")
		return
	}
	ctx := r.Context()
	d, err := s.checkCode(ctx, e.Header.Security.UsernameToken.Password)
	if err != nil {
		s.fault(w, e, actionEnroll, "s:Authentication", "the enrollment code is wrong or expired")
		return
	}
	bst := e.Body.RST.BinarySecurityToken
	if bst.ValueType != valuePKCS10 {
		s.fault(w, e, actionEnroll, "s:CertificateRequest", "only PKCS#10 requests are supported")
		return
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(bst.Value), ""))
	var csr *x509.CertificateRequest
	if err == nil {
		csr, err = x509.ParseCertificateRequest(der)
	}
	if err != nil {
		s.fault(w, e, actionEnroll, "s:CertificateRequest", "the certificate request is not readable")
		return
	}
	now := s.Clock.Now()
	cert, err := s.CA.Sign(csr, d.ID, now, s.certValidity())
	if err != nil {
		s.log().Warn("windows enroll: sign", "device", d.ID, "err", err)
		s.fault(w, e, actionEnroll, "s:CertificateRequest", "the certificate request was rejected")
		return
	}
	digest := make([]byte, 18)
	_, _ = rand.Read(digest)
	doc := buildProvisioningDoc(provisionInput{
		CACert: s.CA.Cert.Raw, ClientCert: cert.Raw, DeviceStore: e.context("EnrollmentType") == "Device",
		DeviceID: d.ID, ManageURL: s.BaseURL + PathManagement, ProviderID: s.providerID(), ServerName: "mdm",
		PollMinutes: s.pollMinutes(), DigestUser: d.ID, DigestPass: base64.RawURLEncoding.EncodeToString(digest),
	})
	// 合言葉は使い切り。以後は証明書で確かめる。
	if err := s.Store.DeleteEnrollmentCodes(ctx, d.ID); err != nil {
		s.fault(w, e, actionEnroll, "s:InternalServiceFault", "internal error")
		return
	}
	m := core.Managed{
		DeviceID: d.ID, Provider: Provider, ExternalID: e.context("DeviceID"), State: core.ManagedPending, Mode: ModeMDMOnly,
		OSVersion: e.context("OSVersion"), CertFingerprints: []string{Fingerprint(cert)}, EnrolledAt: now,
	}
	if err := s.Store.CancelCommands(ctx, d.ID); err != nil {
		s.fault(w, e, actionEnroll, "s:InternalServiceFault", "internal error")
		return
	}
	if err := s.Store.PutManaged(ctx, m); err != nil {
		s.fault(w, e, actionEnroll, "s:InternalServiceFault", "internal error")
		return
	}
	s.log().Info("windows enrolled", "device", d.ID, "windows_device_id", m.ExternalID)
	writeSOAP(w, http.StatusOK, render("enroll", map[string]string{
		"RelatesTo": e.Header.MessageID, "Created": soapTime(now), "Expires": soapTime(now.Add(5 * time.Minute)), "ProvDoc": doc,
	}))
}

func (s *Service) pollMinutes() int {
	if s.PollMinutes <= 0 {
		return 15
	}
	return s.PollMinutes
}

// --- 管理

// authenticate は TLS のクライアント証明書で端末を確かめる。
func (s *Service) authenticate(r *http.Request) (core.Managed, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return core.Managed{}, errors.New("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	id, err := s.CA.Verify(cert, s.Clock.Now())
	if err != nil {
		return core.Managed{}, err
	}
	m, err := s.Store.GetManaged(r.Context(), id)
	if err != nil {
		return core.Managed{}, err
	}
	if m.Provider != Provider || m.State == core.ManagedRemoved {
		return core.Managed{}, errors.New("not managed")
	}
	fp := Fingerprint(cert)
	for _, f := range m.CertFingerprints {
		if f == fp {
			return m, nil
		}
	}
	return core.Managed{}, errors.New("certificate was replaced")
}

func (s *Service) manage(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticate(r)
	if err != nil {
		s.log().Info("windows manage: rejected", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	in, err := parseSyncML(b)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out, err := s.session(r.Context(), m, in)
	if err != nil {
		s.log().Error("windows manage", "device", m.DeviceID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", syncmlType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

// session は端末からの 1 つのメッセージを処理し、答えを返す。
func (s *Service) session(ctx context.Context, m core.Managed, in *syncML) ([]byte, error) {
	now := s.Clock.Now()
	d, err := s.Store.GetDevice(ctx, m.DeviceID)
	if err != nil {
		return nil, err
	}
	out := newReply(in, s.BaseURL+PathManagement)
	sessionStart, userUnenrolled := false, false
	for _, c := range in.Body.Cmds {
		switch c.XMLName.Local {
		case "Status":
			if err := s.onStatus(ctx, &m, c, now); err != nil {
				return nil, err
			}
		case "Results":
			if err := s.onResults(ctx, &m, c, now); err != nil {
				return nil, err
			}
		case "Alert":
			out.status(c.CmdID, "Alert", "200")
			switch c.Data.text() {
			case "1200", "1201":
				sessionStart = true
			case "1226", "1224":
				for _, it := range c.Items {
					if it.Meta != nil && it.Meta.Type == "com.microsoft:mdm.unenrollment.userrequest" {
						userUnenrolled = true
					}
				}
			}
		default:
			out.status(c.CmdID, c.XMLName.Local, "200")
		}
	}

	if userUnenrolled || m.State == core.ManagedRemoved {
		// 利用者が設定から管理を外した。
		m.State = core.ManagedRemoved
		m.CertFingerprints = nil
		if err := s.Store.CancelCommands(ctx, d.ID); err != nil {
			return nil, err
		}
		return out.bytes(), s.Store.PutManaged(ctx, m)
	}

	if m.State == core.ManagedPending {
		m.State = core.ManagedActive
	}
	if sessionStart && m.State == core.ManagedActive {
		if err := s.queuePolicy(ctx, &m, d, now); err != nil {
			return nil, err
		}
		if now.Sub(m.InventoryAt) >= time.Hour {
			if err := s.queueInventory(ctx, &m, now); err != nil {
				return nil, err
			}
		}
	}

	next, err := s.Store.NextCommands(ctx, d.ID, now.Add(-30*time.Minute), 50)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, c := range next {
		out.command(commandCmd(cmdIDFor(c.ID), c.Verb, c.LocURI, c.Format, c.Data))
		ids = append(ids, c.ID)
	}
	if err := s.Store.MarkCommandsSent(ctx, ids, now); err != nil {
		return nil, err
	}
	m.ReportedAt = now
	if err := s.Store.TouchDevice(ctx, d.ID, now); err != nil {
		return nil, err
	}
	if err := s.updateCompliance(ctx, &m); err != nil {
		return nil, err
	}
	return out.bytes(), s.Store.PutManaged(ctx, m)
}

func cmdIDFor(id int64) string { return "m" + strconv.FormatInt(id, 10) }

func parseCmdID(s string) (int64, bool) {
	rest, ok := strings.CutPrefix(s, "m")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil
}

func (s *Service) onStatus(ctx context.Context, m *core.Managed, c syncCmd, now time.Time) error {
	id, ok := parseCmdID(c.CmdRef)
	if !ok {
		return nil // SyncHdr などへの答え
	}
	code := c.Data.text()
	state := core.CommandDone
	ok200 := code == "200" || code == "202"
	cmd, err := s.Store.GetCommand(ctx, m.DeviceID, id)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ok200 && !(cmd.Verb == "Delete" && code == "404") {
		state = core.CommandFailed
	}
	cmd, err = s.Store.FinishCommand(ctx, m.DeviceID, id, state, code, "", now)
	if err != nil {
		return err
	}
	switch cmd.Purpose {
	case purposePolicy:
		if state == core.CommandFailed {
			m.Problems = appendUnique(m.Problems, cmd.LocURI+": "+code)
		}
	case purposeUnenroll:
		if state == core.CommandDone {
			m.State = core.ManagedRemoved
		}
	}
	return nil
}

func (s *Service) onResults(ctx context.Context, m *core.Managed, c syncCmd, now time.Time) error {
	id, ok := parseCmdID(c.CmdRef)
	if !ok || len(c.Items) == 0 {
		return nil
	}
	val := c.Items[0].Data.text()
	cmd, err := s.Store.FinishCommand(ctx, m.DeviceID, id, core.CommandDone, "", val, now)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if cmd.Purpose != purposeInventory {
		return nil
	}
	switch cmd.LocURI {
	case uriOSVersion:
		m.OSVersion = val
	case uriMan, uriMod:
		m.Model = s.model(ctx, m.DeviceID)
	case uriEncryption:
		m.Encrypted = val == "1"
	}
	return nil
}

// model は最後に問い合わせた製造元と機種（"Man Mod"）。2 つの答えは別々に届くので、記録から組み立てる。
func (s *Service) model(ctx context.Context, deviceID string) string {
	cmds, err := s.Store.ListCommands(ctx, deviceID, 100)
	if err != nil {
		return ""
	}
	parts := map[string]string{}
	for _, c := range cmds { // 新しい順
		if c.Purpose == purposeInventory && c.State == core.CommandDone && c.Result != "" {
			if _, seen := parts[c.LocURI]; !seen {
				parts[c.LocURI] = c.Result
			}
		}
	}
	return strings.TrimSpace(parts[uriMan] + " " + parts[uriMod])
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// queuePolicy はポリシーが変わっていれば、設定の命令を待ち行列に入れる。
func (s *Service) queuePolicy(ctx context.Context, m *core.Managed, d core.Device, now time.Time) error {
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return err
	}
	ss := buildSettings(pol)
	h := settingsHash(ss)
	if h == m.PolicyHash {
		return nil
	}
	cmds := make([]core.DeviceCommand, 0, len(ss))
	for _, x := range ss {
		cmds = append(cmds, core.DeviceCommand{DeviceID: d.ID, Verb: x.Verb, LocURI: x.URI, Format: x.Format, Data: x.Data, Purpose: purposePolicy, CreatedAt: now})
	}
	if _, err := s.Store.EnqueueCommands(ctx, cmds); err != nil {
		return err
	}
	m.PolicyHash = h
	m.Problems = nil
	m.PolicyCompliant = false
	return nil
}

func (s *Service) queueInventory(ctx context.Context, m *core.Managed, now time.Time) error {
	cmds := make([]core.DeviceCommand, 0, len(inventoryURIs))
	for _, u := range inventoryURIs {
		cmds = append(cmds, core.DeviceCommand{DeviceID: m.DeviceID, Verb: "Get", LocURI: u, Purpose: purposeInventory, CreatedAt: now})
	}
	if _, err := s.Store.EnqueueCommands(ctx, cmds); err != nil {
		return err
	}
	m.InventoryAt = now
	return nil
}

// updateCompliance は、配った設定がすべて受け入れられたかを見る。
func (s *Service) updateCompliance(ctx context.Context, m *core.Managed) error {
	if len(m.Problems) > 0 {
		m.PolicyCompliant = false
		return nil
	}
	cmds, err := s.Store.ListCommands(ctx, m.DeviceID, 200)
	if err != nil {
		return err
	}
	for _, c := range cmds {
		if c.Purpose == purposePolicy && (c.State == core.CommandPending || c.State == core.CommandSent) {
			m.PolicyCompliant = false
			return nil
		}
	}
	m.PolicyCompliant = m.PolicyHash != ""
	return nil
}

// --- 管理の API から使うもの

// Managed は端末の管理の状態。無ければ ok が false。
func (s *Service) Managed(ctx context.Context, d core.Device) (core.Managed, bool, error) {
	m, err := s.Store.GetManaged(ctx, d.ID)
	if errors.Is(err, core.ErrNotFound) || err == nil && m.Provider != Provider {
		return m, false, nil
	}
	return m, err == nil, err
}

// 命令の種類。
const (
	CommandReboot = "reboot"
	CommandWipe   = "wipe"
)

// Command は命令を待ち行列に入れる。端末が次に通信してきたときに送る。
func (s *Service) Command(ctx context.Context, d core.Device, typ string) error {
	m, ok, err := s.Managed(ctx, d)
	if err != nil {
		return err
	}
	if !ok || m.State != core.ManagedActive && m.State != core.ManagedPending {
		return ErrNotManaged
	}
	c := core.DeviceCommand{DeviceID: d.ID, Verb: "Exec", Format: "null", CreatedAt: s.Clock.Now()}
	switch typ {
	case CommandReboot:
		c.LocURI, c.Purpose = "./Device/Vendor/MSFT/Reboot/RebootNow", purposeReboot
	case CommandWipe:
		c.LocURI, c.Purpose = "./Device/Vendor/MSFT/RemoteWipe/doWipe", purposeWipe
	default:
		return fmt.Errorf("windows: 知らない命令 %q", typ)
	}
	_, err = s.Store.EnqueueCommands(ctx, []core.DeviceCommand{c})
	return err
}

// Unenroll は管理を外す。端末が次に通信してきたときに外れる。force なら待たずに外す（端末の側には管理が残る）。
func (s *Service) Unenroll(ctx context.Context, d core.Device, force bool) error {
	m, ok, err := s.Managed(ctx, d)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotManaged
	}
	if err := s.Store.DeleteEnrollmentCodes(ctx, d.ID); err != nil {
		return err
	}
	if err := s.Store.CancelCommands(ctx, d.ID); err != nil {
		return err
	}
	if force || m.State == core.ManagedRemoved || m.State == core.ManagedPending && m.ReportedAt.IsZero() {
		return s.Store.DeleteManaged(ctx, d.ID)
	}
	pid := s.providerID()
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{{
		DeviceID: d.ID, Verb: "Exec", LocURI: "./Device/Vendor/MSFT/DMClient/Provider/" + pid + "/Unenroll",
		Format: "chr", Data: pid, Purpose: purposeUnenroll, CreatedAt: s.Clock.Now(),
	}}); err != nil {
		return err
	}
	m.State = core.ManagedUnenrolling
	return s.Store.PutManaged(ctx, m)
}
