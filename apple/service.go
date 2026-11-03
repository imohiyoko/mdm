// Package apple は Apple の MDM で iPhone・iPad・Mac を管理する。
//
// 登録：管理者が端末ごとに登録のプロファイルの URL（1 回だけ使える）を作り、利用者が端末で開いて入れる。
// プロファイルには MDM の認証局が発行した端末の証明書が入っていて、以後の通信はその証明書（TLS の
// クライアント証明書）で端末を確かめる。
//
// 管理：Apple の端末は、サーバーからの通知（APNs）を受けたときだけ命令を取りに来る。命令を待ち行列に
// 入れたら通知を送り、端末が来たら 1 つずつ渡して答えを受け取る。
package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
	"github.com/imohiyoko/mdm/pki"
)

// Provider は core.Managed の Provider の値。
const Provider = "apple"

// 道。
const (
	PathEnroll  = "/apple/enroll/"
	PathCheckIn = "/apple/checkin"
	PathServer  = "/apple/mdm"
)

// ErrNotManaged は端末が Apple の管理の下に無い。
var ErrNotManaged = errors.New("apple: 端末は Apple の管理の下に無い")

// Service は Apple の管理。
type Service struct {
	Store  core.Store
	Engine *filter.Engine
	Clock  core.Clock
	CA     *pki.CA
	Pusher Pusher
	// Topic は通知用の証明書の UID。登録のプロファイルに入れる。
	Topic string
	// BaseURL は端末から届く https://host[:port]。
	BaseURL string
	// DoHBaseURL があれば、通信フィルター（DoH）を端末に設定する。{DoHBaseURL}/dns-query/{token}。
	DoHBaseURL string
	Logger     *slog.Logger

	once sync.Once
	kick chan struct{}
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// --- 登録

// Enrollment は利用者に渡す登録の情報。
type Enrollment struct {
	// ProfileURL を端末の Safari（Mac はブラウザー）で開き、プロファイルを入れる。1 回だけ取り出せる。
	ProfileURL string    `json:"profile_url"`
	ExpiresAt  time.Time `json:"expires_at"`
	// FilterEnforced は通信フィルターを端末に設定するか。監視モードの端末では外せない。
	FilterEnforced bool `json:"filter_enforced"`
}

func codeHash(code string) []byte {
	sum := sha256.Sum256([]byte("apple-enroll:" + code))
	return sum[:]
}

// CreateEnrollment は登録のプロファイルの URL を作る。dohToken が空でなければ、登録が済んだあとに
// 通信フィルターのプロファイルを入れる命令を待ち行列に入れておく。
func (s *Service) CreateEnrollment(ctx context.Context, d core.Device, dohToken string, ttl time.Duration) (Enrollment, error) {
	if d.Platform != core.PlatformIOS && d.Platform != core.PlatformMacOS {
		return Enrollment{}, errors.New("apple: iPhone・iPad・Mac の端末ではない")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if m, err := s.Store.GetManaged(ctx, d.ID); err == nil && m.State != core.ManagedRemoved && m.State != core.ManagedPending {
		return Enrollment{}, fmt.Errorf("%w: 端末はもう登録されている（先に管理を外す）", core.ErrConflict)
	} else if err != nil && !errors.Is(err, core.ErrNotFound) {
		return Enrollment{}, err
	}
	if err := s.Store.DeleteEnrollmentCodes(ctx, d.ID); err != nil {
		return Enrollment{}, err
	}
	if err := s.Store.CancelCommands(ctx, d.ID); err != nil {
		return Enrollment{}, err
	}
	code, _ := core.NewFilterToken()
	now := s.Clock.Now()
	if err := s.Store.PutEnrollmentCode(ctx, core.EnrollmentCode{Hash: codeHash(code), DeviceID: d.ID, ExpiresAt: now.Add(ttl)}); err != nil {
		return Enrollment{}, err
	}
	enforced := false
	if dohToken != "" && s.DoHBaseURL != "" {
		if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{s.dnsCommand(d.ID, dohToken, now)}); err != nil {
			return Enrollment{}, err
		}
		enforced = true
	}
	return Enrollment{ProfileURL: s.BaseURL + PathEnroll + code + ".mobileconfig", ExpiresAt: now.Add(ttl), FilterEnforced: enforced}, nil
}

func (s *Service) dnsCommand(deviceID, dohToken string, now time.Time) core.DeviceCommand {
	return core.DeviceCommand{
		DeviceID: deviceID, Verb: "InstallProfile", Purpose: purposeDNS, CreatedAt: now,
		Data: installProfile(dnsProfile(deviceID, s.DoHBaseURL+"/dns-query/"+dohToken)),
	}
}

// 命令の目的。
const (
	purposePolicy    = "policy"
	purposeDNS       = "dns"
	purposeInventory = "inventory"
	purposeSecurity  = "security"
	purposeLock      = "lock"
	purposeRestart   = "restart"
	purposeWipe      = "wipe"
	purposeUnenroll  = "unenroll"
)

// Handler は登録のプロファイル・チェックイン・命令の http.Handler。チェックインと命令は TLS のクライアント証明書が要る。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathEnroll+"{file}", s.enrollProfile)
	mux.HandleFunc("PUT "+PathCheckIn, s.checkIn)
	mux.HandleFunc("PUT "+PathServer, s.server)
	return mux
}

func (s *Service) enrollProfile(w http.ResponseWriter, r *http.Request) {
	code, ok := strings.CutSuffix(r.PathValue("file"), ".mobileconfig")
	if !ok || !core.LooksLikeFilterToken(code) {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	c, err := s.Store.GetEnrollmentCode(ctx, codeHash(code))
	if err != nil || !s.Clock.Now().Before(c.ExpiresAt) {
		http.NotFound(w, r)
		return
	}
	// 1 回だけ。端末の証明書を作って入れるので、取り出したら合言葉を消す。
	if err := s.Store.DeleteEnrollmentCodes(ctx, c.DeviceID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	profile, fp, err := s.buildEnrollProfile(c.DeviceID)
	if err != nil {
		s.log().Error("apple enroll profile", "device", c.DeviceID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	m := core.Managed{DeviceID: c.DeviceID, Provider: Provider, State: core.ManagedPending, CertFingerprints: []string{fp}}
	if err := s.Store.PutManaged(ctx, m); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="mdm.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(profile)
}

func (s *Service) buildEnrollProfile(deviceID string) ([]byte, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	cert, err := s.CA.Issue(&key.PublicKey, deviceID, s.Clock.Now(), 5*365*24*time.Hour)
	if err != nil {
		return nil, "", err
	}
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw)
	// 古い iOS でも読めるように、昔からの暗号（3DES）で包む。中身はこのプロファイルにしか入らない。
	p12, err := pkcs12.LegacyDES.Encode(key, cert, []*x509.Certificate{s.CA.Cert}, pass)
	if err != nil {
		return nil, "", err
	}
	return enrollProfile(enrollInput{
		DeviceID: deviceID, P12: p12, P12Pass: pass, Topic: s.Topic,
		ServerURL: s.BaseURL + PathServer, CheckInURL: s.BaseURL + PathCheckIn,
	}), pki.Fingerprint(cert), nil
}

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
	fp := pki.Fingerprint(cert)
	for _, f := range m.CertFingerprints {
		if f == fp {
			return m, nil
		}
	}
	return core.Managed{}, errors.New("certificate was replaced")
}

func readPlist(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	var m map[string]any
	if _, err := plist.Unmarshal(b, &m); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return m, true
}

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

// --- チェックイン

func (s *Service) checkIn(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticate(r)
	if err != nil {
		s.log().Info("apple checkin: rejected", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	msg, ok := readPlist(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if str(msg, "UserID") != "" || str(msg, "UserShortName") != "" {
		// Mac の利用者ごとの通信。いまは使わない。
		w.WriteHeader(http.StatusOK)
		return
	}
	switch str(msg, "MessageType") {
	case "Authenticate":
		m.ExternalID = str(msg, "UDID")
		m.Model = str(msg, "ProductName")
		m.OSVersion = str(msg, "OSVersion")
		m.EnrolledAt = s.Clock.Now()
	case "TokenUpdate":
		if tok, ok := msg["Token"].([]byte); ok {
			m.PushToken = hex.EncodeToString(tok)
		}
		if pm := str(msg, "PushMagic"); pm != "" {
			m.PushMagic = pm
		}
		if m.State == core.ManagedPending {
			m.State = core.ManagedActive
			if err := s.prepare(ctx, &m); err != nil {
				s.log().Error("apple prepare", "device", m.DeviceID, "err", err)
			}
		}
	case "CheckOut":
		m.State = core.ManagedRemoved
		m.CertFingerprints = nil
		if err := s.Store.CancelCommands(ctx, m.DeviceID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if err := s.Store.PutManaged(ctx, m); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if str(msg, "MessageType") == "TokenUpdate" && m.State == core.ManagedActive {
		s.Kick()
	}
	w.WriteHeader(http.StatusOK)
}

// prepare は端末に最初に送る命令（ポリシーと端末の情報の問い合わせ）を待ち行列に入れる。
func (s *Service) prepare(ctx context.Context, m *core.Managed) error {
	d, err := s.Store.GetDevice(ctx, m.DeviceID)
	if err != nil {
		return err
	}
	if err := s.queuePolicy(ctx, m, d); err != nil {
		return err
	}
	return s.queueInventory(ctx, m)
}

// --- 命令のやり取り

func (s *Service) server(w http.ResponseWriter, r *http.Request) {
	m, err := s.authenticate(r)
	if err != nil {
		s.log().Info("apple mdm: rejected", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	msg, ok := readPlist(w, r)
	if !ok {
		return
	}
	if str(msg, "UserID") != "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	out, err := s.exchange(r.Context(), m, msg)
	if err != nil {
		s.log().Error("apple mdm", "device", m.DeviceID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if out == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(out)
}

func cmdUUID(id int64) string { return "m" + strconv.FormatInt(id, 10) }

func parseUUID(s string) (int64, bool) {
	rest, ok := strings.CutPrefix(s, "m")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil
}

// exchange は端末の答えを記録し、次の命令を返す（無ければ nil）。
func (s *Service) exchange(ctx context.Context, m core.Managed, msg map[string]any) ([]byte, error) {
	now := s.Clock.Now()
	status := str(msg, "Status")
	if id, ok := parseUUID(str(msg, "CommandUUID")); ok && status != "Idle" {
		switch status {
		case "NotNow":
			// 端末が今はできない（画面がロックされているなど）。あとで送り直す。
			if err := s.Store.RequeueCommand(ctx, m.DeviceID, id); err != nil {
				return nil, err
			}
			return nil, s.Store.PutManaged(ctx, m)
		case "Acknowledged":
			if err := s.acknowledged(ctx, &m, id, msg, now); err != nil {
				return nil, err
			}
		default: // Error・CommandFormatError
			c, err := s.Store.FinishCommand(ctx, m.DeviceID, id, core.CommandFailed, status, errorChain(msg), now)
			if err != nil && !errors.Is(err, core.ErrNotFound) {
				return nil, err
			}
			if err == nil && (c.Purpose == purposePolicy || c.Purpose == purposeDNS) {
				m.Problems = appendUnique(m.Problems, c.Purpose+": "+errorChain(msg))
			}
		}
	}
	m.ReportedAt = now
	if err := s.Store.TouchDevice(ctx, m.DeviceID, now); err != nil {
		return nil, err
	}
	if m.State == core.ManagedRemoved {
		return nil, s.Store.PutManaged(ctx, m)
	}
	next, err := s.Store.NextCommands(ctx, m.DeviceID, now.Add(-30*time.Minute), 1)
	if err != nil {
		return nil, err
	}
	if err := s.updateCompliance(ctx, &m); err != nil {
		return nil, err
	}
	if err := s.Store.PutManaged(ctx, m); err != nil {
		return nil, err
	}
	if len(next) == 0 {
		return nil, nil
	}
	c := next[0]
	var body map[string]any
	if _, err := plist.Unmarshal([]byte(c.Data), &body); err != nil {
		return nil, fmt.Errorf("command %d: %w", c.ID, err)
	}
	if err := s.Store.MarkCommandsSent(ctx, []int64{c.ID}, now); err != nil {
		return nil, err
	}
	return encode(map[string]any{"CommandUUID": cmdUUID(c.ID), "Command": body}), nil
}

func errorChain(msg map[string]any) string {
	chain, _ := msg["ErrorChain"].([]any)
	var parts []string
	for _, e := range chain {
		if d, ok := e.(map[string]any); ok {
			parts = append(parts, strings.TrimSpace(describe(d["ErrorDomain"])+" "+describe(d["ErrorCode"])+" "+str(d, "LocalizedDescription")))
		}
	}
	if len(parts) == 0 {
		return str(msg, "Status")
	}
	return strings.Join(parts, "; ")
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (s *Service) acknowledged(ctx context.Context, m *core.Managed, id int64, msg map[string]any, now time.Time) error {
	c, err := s.Store.FinishCommand(ctx, m.DeviceID, id, core.CommandDone, "Acknowledged", "", now)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	switch c.Purpose {
	case purposeDNS:
		// 中身に DoH の秘密が入っているので、送り終えたら消す。
		return s.Store.ClearCommandData(ctx, m.DeviceID, id)
	case purposeInventory:
		q, _ := msg["QueryResponses"].(map[string]any)
		if v := str(q, "OSVersion"); v != "" {
			m.OSVersion = v
		}
		if v := str(q, "ModelName"); v != "" {
			m.Model = v
		}
		if v, ok := q["IsSupervised"].(bool); ok {
			m.Supervised = v
			if v {
				m.Mode = "supervised"
			} else {
				m.Mode = "device"
			}
		}
	case purposeSecurity:
		si, _ := msg["SecurityInfo"].(map[string]any)
		if v, ok := si["PasscodePresent"].(bool); ok {
			m.ScreenLock = v
			// iPhone・iPad はパスコードがあればデータが暗号化される（ハードウェアの暗号化）。
			m.Encrypted = v
		}
		if v, ok := si["FDE_Enabled"].(bool); ok { // Mac の FileVault
			m.Encrypted = v
		}
	case purposeUnenroll:
		m.State = core.ManagedRemoved
		m.CertFingerprints = nil
		return s.Store.CancelCommands(ctx, m.DeviceID)
	}
	return nil
}

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
		if (c.Purpose == purposePolicy || c.Purpose == purposeDNS) && (c.State == core.CommandPending || c.State == core.CommandSent) {
			m.PolicyCompliant = false
			return nil
		}
	}
	m.PolicyCompliant = m.PolicyHash != ""
	return nil
}

// --- 配布と通知

func profileHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func (s *Service) queuePolicy(ctx context.Context, m *core.Managed, d core.Device) error {
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return err
	}
	prof := policyProfile(d.ID, pol)
	h := profileHash(prof)
	if h == m.PolicyHash {
		return nil
	}
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{{
		DeviceID: d.ID, Verb: "InstallProfile", Purpose: purposePolicy, Data: installProfile(prof), CreatedAt: s.Clock.Now(),
	}}); err != nil {
		return err
	}
	m.PolicyHash = h
	m.Problems = nil
	m.PolicyCompliant = false
	return nil
}

var deviceQueries = []string{"DeviceName", "OSVersion", "BuildVersion", "ProductName", "ModelName", "Model", "SerialNumber", "IsSupervised"}

func (s *Service) queueInventory(ctx context.Context, m *core.Managed) error {
	now := s.Clock.Now()
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{
		{DeviceID: m.DeviceID, Verb: "DeviceInformation", Purpose: purposeInventory, Data: command("DeviceInformation", map[string]any{"Queries": deviceQueries}), CreatedAt: now},
		{DeviceID: m.DeviceID, Verb: "SecurityInfo", Purpose: purposeSecurity, Data: command("SecurityInfo", nil), CreatedAt: now},
	}); err != nil {
		return err
	}
	m.InventoryAt = now
	return nil
}

func (s *Service) kickCh() chan struct{} {
	s.once.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// Kick は配り直しと通知を頼む（すぐ戻る）。
func (s *Service) Kick() {
	select {
	case s.kickCh() <- struct{}{}:
	default:
	}
}

// Run は interval ごとと Kick されたときに、ポリシーの変更・端末の情報の問い合わせを待ち行列に入れ、命令のある端末に通知する。
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.SyncAll(ctx); err != nil {
			s.log().Error("apple sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kickCh():
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// SyncAll は管理している端末ごとに、変わったポリシーと期限の来た問い合わせを待ち行列に入れ、命令があれば通知する。
func (s *Service) SyncAll(ctx context.Context) error {
	ms, err := s.Store.ListManaged(ctx, Provider)
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range ms {
		if m.State != core.ManagedActive && m.State != core.ManagedUnenrolling {
			continue
		}
		if err := s.syncOne(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.DeviceID, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) syncOne(ctx context.Context, m core.Managed) error {
	before := m.PolicyHash + m.InventoryAt.String()
	if m.State == core.ManagedActive {
		d, err := s.Store.GetDevice(ctx, m.DeviceID)
		if err != nil {
			return err
		}
		if err := s.queuePolicy(ctx, &m, d); err != nil {
			return err
		}
		if s.Clock.Now().Sub(m.InventoryAt) >= 6*time.Hour {
			if err := s.queueInventory(ctx, &m); err != nil {
				return err
			}
		}
		if m.PolicyHash+m.InventoryAt.String() != before {
			if err := s.Store.PutManaged(ctx, m); err != nil {
				return err
			}
		}
	}
	next, err := s.Store.NextCommands(ctx, m.DeviceID, s.Clock.Now().Add(-30*time.Minute), 1)
	if err != nil || len(next) == 0 {
		return err
	}
	return s.push(ctx, m)
}

func (s *Service) push(ctx context.Context, m core.Managed) error {
	if s.Pusher == nil || m.PushToken == "" || m.PushMagic == "" {
		return nil
	}
	tok, err := hex.DecodeString(m.PushToken)
	if err != nil {
		return err
	}
	return s.Pusher.Push(ctx, tok, m.PushMagic)
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
	CommandLock    = "lock"
	CommandRestart = "reboot"
	CommandWipe    = "wipe"
)

// Command は命令を待ち行列に入れて、端末に通知する。
func (s *Service) Command(ctx context.Context, d core.Device, typ string) error {
	m, ok, err := s.Managed(ctx, d)
	if err != nil {
		return err
	}
	if !ok || m.State != core.ManagedActive {
		return ErrNotManaged
	}
	c := core.DeviceCommand{DeviceID: d.ID, CreatedAt: s.Clock.Now()}
	switch typ {
	case CommandLock:
		c.Verb, c.Purpose, c.Data = "DeviceLock", purposeLock, command("DeviceLock", nil)
	case CommandRestart:
		c.Verb, c.Purpose, c.Data = "RestartDevice", purposeRestart, command("RestartDevice", nil)
	case CommandWipe:
		c.Verb, c.Purpose, c.Data = "EraseDevice", purposeWipe, command("EraseDevice", nil)
	default:
		return fmt.Errorf("apple: 知らない命令 %q", typ)
	}
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{c}); err != nil {
		return err
	}
	s.pushLater(ctx, m)
	return nil
}

// pushLater は通知を送る。失敗しても、命令は待ち行列にあるので、定期の配り直しでもう一度通知する。
func (s *Service) pushLater(ctx context.Context, m core.Managed) {
	if err := s.push(ctx, m); err != nil {
		s.log().Warn("apple push", "device", m.DeviceID, "err", err)
	}
}

// SetFilterToken は作り直した DoH の秘密を端末に配る。Apple の管理の下に無い端末では何もしない。
func (s *Service) SetFilterToken(ctx context.Context, d core.Device, dohToken string) error {
	m, ok, err := s.Managed(ctx, d)
	if err != nil || !ok || m.State != core.ManagedActive || s.DoHBaseURL == "" {
		return err
	}
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{s.dnsCommand(d.ID, dohToken, s.Clock.Now())}); err != nil {
		return err
	}
	s.pushLater(ctx, m)
	return nil
}

// Unenroll は管理を外す。登録のプロファイルを消す命令を送り、端末が受け取ると外れる。
// force なら待たずに MDM の側だけ外す。
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
	if force || m.State == core.ManagedRemoved || m.State == core.ManagedPending || m.PushToken == "" {
		return s.Store.DeleteManaged(ctx, d.ID)
	}
	if _, err := s.Store.EnqueueCommands(ctx, []core.DeviceCommand{{
		DeviceID: d.ID, Verb: "RemoveProfile", Purpose: purposeUnenroll, CreatedAt: s.Clock.Now(),
		Data: command("RemoveProfile", map[string]any{"Identifier": EnrollIdentifier}),
	}}); err != nil {
		return err
	}
	m.State = core.ManagedUnenrolling
	if err := s.Store.PutManaged(ctx, m); err != nil {
		return err
	}
	s.pushLater(ctx, m)
	return nil
}
