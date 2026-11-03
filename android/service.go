package android

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// Provider は core.Managed の Provider の値。
const Provider = "android"

// 登録の方法。
const (
	// ModeFullyManaged は会社・家の端末を丸ごと管理する。初期化した端末で QR コードを読む。
	ModeFullyManaged = "fully_managed"
	// ModeWorkProfile は私物の端末の中に仕事用の領域を作り、その中だけを管理する。
	ModeWorkProfile = "work_profile"
)

var (
	// ErrNoEnterprise は組織の Android の管理がまだ始まっていない。
	ErrNoEnterprise = errors.New("android: この組織は Android の管理をまだ始めていない")
	// ErrBadSignup は登録の画面から戻ってきた内容が使えない（期限切れ・使用済みなど）。
	ErrBadSignup = errors.New("android: 申し込みが見つからないか期限が切れている")
	// ErrNotManaged は端末が Android の管理の下に無い。
	ErrNotManaged = errors.New("android: 端末は Android の管理の下に無い")
)

// Service は Android の管理。組織の enterprise・端末の登録・ポリシーの配布・状態の取り込み・命令を受け持つ。
type Service struct {
	Store  core.Store
	Client *Client
	Engine *filter.Engine
	Clock  core.Clock
	// ProjectID は AMAPI を有効にした Google Cloud のプロジェクト。
	ProjectID string
	// CallbackURL は enterprise を作ったあとに戻る https の URL（公開の入り口の /android/signup/callback）。
	CallbackURL string
	// DoTDomain が空でなければ、端末の Private DNS を {label}.{DoTDomain} に固定する。
	DoTDomain string
	Logger    *slog.Logger

	once sync.Once
	kick chan struct{}
}

func (s *Service) kickCh() chan struct{} {
	s.once.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// Kick はポリシーの配り直しを頼む（すぐ戻る）。管理の API で変更があったときに呼ぶ。
func (s *Service) Kick() {
	select {
	case s.kickCh() <- struct{}{}:
	default:
	}
}

// Run は interval ごとに端末の状態を取り込んでポリシーを配り直し、Kick されたら配り直す。
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	s.syncAndPush(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncAndPush(ctx)
		case <-s.kickCh():
			// 続けて変更されることが多いので、少し待ってからまとめて配る。
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if err := s.PushAll(ctx); err != nil {
				s.log().Error("android push", "err", err)
			}
		}
	}
}

func (s *Service) syncAndPush(ctx context.Context) {
	if err := s.Sync(ctx); err != nil {
		s.log().Error("android sync", "err", err)
	}
	if err := s.PushAll(ctx); err != nil {
		s.log().Error("android push", "err", err)
	}
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// --- enterprise

// StartSignup は組織の enterprise を作る Google の画面の URL を返す。管理者がそれを開いて進める。
func (s *Service) StartSignup(ctx context.Context, orgID, adminEmail string) (string, error) {
	if _, err := s.Store.GetAndroidEnterprise(ctx, orgID); err == nil {
		return "", fmt.Errorf("%w: この組織はもう Android の管理を始めている", core.ErrConflict)
	} else if !errors.Is(err, core.ErrNotFound) {
		return "", err
	}
	state, hash := core.NewFilterToken()
	cb := s.CallbackURL + "?" + url.Values{"state": {state}}.Encode()
	su, err := s.Client.CreateSignupURL(ctx, s.ProjectID, cb, adminEmail)
	if err != nil {
		return "", err
	}
	err = s.Store.CreateAndroidSignup(ctx, core.AndroidSignup{
		StateHash: hash, OrgID: orgID, SignupURLName: su.Name, ExpiresAt: s.Clock.Now().Add(time.Hour),
	})
	return su.URL, err
}

// FinishSignup は Google の画面から戻ってきたときに enterprise を作り、組織に結びつける。
func (s *Service) FinishSignup(ctx context.Context, state, enterpriseToken string) (core.AndroidEnterprise, error) {
	var e core.AndroidEnterprise
	if !core.LooksLikeFilterToken(state) || enterpriseToken == "" {
		return e, ErrBadSignup
	}
	a, err := s.Store.TakeAndroidSignup(ctx, core.HashFilterToken(state))
	if errors.Is(err, core.ErrNotFound) {
		return e, ErrBadSignup
	}
	if err != nil {
		return e, err
	}
	if !s.Clock.Now().Before(a.ExpiresAt) {
		return e, ErrBadSignup
	}
	if _, err := s.Store.GetAndroidEnterprise(ctx, a.OrgID); err == nil {
		return e, fmt.Errorf("%w: この組織はもう Android の管理を始めている", core.ErrConflict)
	}
	org, err := s.Store.GetOrg(ctx, a.OrgID)
	if err != nil {
		return e, err
	}
	ent, err := s.Client.CreateEnterprise(ctx, s.ProjectID, a.SignupURLName, enterpriseToken, Enterprise{EnterpriseDisplayName: org.Name})
	if err != nil {
		return e, err
	}
	if !strings.HasPrefix(ent.Name, "enterprises/") {
		return e, fmt.Errorf("android: enterprise の名前がおかしい（%q）", ent.Name)
	}
	e = core.AndroidEnterprise{OrgID: a.OrgID, Name: ent.Name, CreatedAt: s.Clock.Now()}
	return e, s.Store.PutAndroidEnterprise(ctx, e)
}

// --- 登録

// EnrollOptions は登録の方法。
type EnrollOptions struct {
	Mode string        // ModeFullyManaged か ModeWorkProfile。空なら完全管理
	TTL  time.Duration // 登録の鍵の有効期間。0 なら 1 時間
}

// Enrollment は端末に読ませる登録の情報。
type Enrollment struct {
	Mode string `json:"mode"`
	// QRCode は QR コードにする JSON。初期化した端末の最初の画面を 6 回たたくと読み取りが始まる。
	QRCode string `json:"qr_code"`
	// URL は私物の端末で開く登録のリンク（仕事用プロファイルを作る）。
	URL       string    `json:"url,omitempty"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	// FilterEnforced は通信フィルター（Private DNS）を端末に固定するか。完全管理で DoT があるときだけ。
	FilterEnforced bool `json:"filter_enforced"`
}

// Enroll は端末 d の AMAPI のポリシーを作り、登録の鍵を作る。dotLabel は新しく作った DoT のラベル（平文）。
func (s *Service) Enroll(ctx context.Context, d core.Device, dotLabel string, opt EnrollOptions) (Enrollment, error) {
	var out Enrollment
	if d.Platform != core.PlatformAndroid {
		return out, errors.New("android: Android の端末ではない")
	}
	if opt.Mode == "" {
		opt.Mode = ModeFullyManaged
	}
	if opt.TTL <= 0 {
		opt.TTL = time.Hour
	}
	ent, err := s.Store.GetAndroidEnterprise(ctx, d.OrgID)
	if errors.Is(err, core.ErrNotFound) {
		return out, ErrNoEnterprise
	}
	if err != nil {
		return out, err
	}
	if m, err := s.Store.GetManaged(ctx, d.ID); err == nil && m.ExternalID != "" && m.State != core.ManagedRemoved {
		return out, fmt.Errorf("%w: 端末はもう登録されている（先に管理を外す）", core.ErrConflict)
	} else if err != nil && !errors.Is(err, core.ErrNotFound) {
		return out, err
	}
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return out, err
	}
	policyName := ent.Name + "/policies/" + d.ID
	host := s.dotHost(dotLabel)
	body, _ := BuildPolicy(pol, host)
	if err := s.Client.PatchPolicy(ctx, policyName, body, nil); err != nil {
		return out, err
	}
	usage := "PERSONAL_USAGE_DISALLOWED"
	if opt.Mode == ModeWorkProfile {
		usage = "PERSONAL_USAGE_ALLOWED"
	}
	tok, err := s.Client.CreateEnrollmentToken(ctx, ent.Name, EnrollmentToken{
		PolicyName: policyName, Duration: fmt.Sprintf("%ds", int(opt.TTL.Seconds())), OneTimeOnly: true,
		AdditionalData: d.ID, AllowPersonalUsage: usage,
	})
	if err != nil {
		return out, err
	}
	base, _ := BuildPolicy(pol, "")
	m := core.Managed{
		DeviceID: d.ID, Provider: Provider, PolicyName: policyName, State: core.ManagedPending, Mode: opt.Mode,
		PolicyHash: policyHash(base),
	}
	if err := s.Store.PutManaged(ctx, m); err != nil {
		return out, err
	}
	out = Enrollment{
		Mode: opt.Mode, QRCode: tok.QRCode, Token: tok.Value, ExpiresAt: s.Clock.Now().Add(opt.TTL),
		FilterEnforced: host != "" && opt.Mode == ModeFullyManaged,
	}
	if t, err := time.Parse(time.RFC3339Nano, tok.ExpirationTime); err == nil {
		out.ExpiresAt = t.UTC()
	}
	if opt.Mode == ModeWorkProfile {
		out.URL = "https://enterprise.google.com/android/enroll?" + url.Values{"et": {tok.Value}}.Encode()
	}
	return out, nil
}

func (s *Service) dotHost(label string) string {
	if s.DoTDomain == "" || label == "" {
		return ""
	}
	return label + "." + s.DoTDomain
}

// SetFilterHost は作り直した DoT のラベルを端末に配る。Android の管理の下に無い端末では何もしない。
func (s *Service) SetFilterHost(ctx context.Context, d core.Device, dotLabel string) error {
	m, err := s.Store.GetManaged(ctx, d.ID)
	if errors.Is(err, core.ErrNotFound) || err == nil && (m.Provider != Provider || m.State == core.ManagedRemoved) {
		return nil
	}
	if err != nil {
		return err
	}
	host := s.dotHost(dotLabel)
	if host == "" {
		return nil
	}
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return err
	}
	body, mask := BuildPolicy(pol, host)
	return s.Client.PatchPolicy(ctx, m.PolicyName, body, mask)
}

// --- 配布

// PushAll はポリシーが変わった端末に配り直す。
func (s *Service) PushAll(ctx context.Context) error {
	ms, err := s.Store.ListManaged(ctx, Provider)
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range ms {
		if m.State == core.ManagedRemoved {
			continue
		}
		if err := s.push(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.DeviceID, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) push(ctx context.Context, m core.Managed) error {
	d, err := s.Store.GetDevice(ctx, m.DeviceID)
	if err != nil {
		return err
	}
	pol, _, err := s.Engine.PolicyFor(ctx, d)
	if err != nil {
		return err
	}
	body, mask := BuildPolicy(pol, "")
	h := policyHash(body)
	if h == m.PolicyHash {
		return nil
	}
	if err := s.Client.PatchPolicy(ctx, m.PolicyName, body, mask); err != nil {
		return err
	}
	m.PolicyHash = h
	return s.Store.PutManaged(ctx, m)
}

// --- 状態の取り込み

// Sync は AMAPI から端末の状態を取り込む。
func (s *Service) Sync(ctx context.Context) error {
	ents, err := s.Store.ListAndroidEnterprises(ctx)
	if err != nil {
		return err
	}
	ms, err := s.Store.ListManaged(ctx, Provider)
	if err != nil {
		return err
	}
	var errs []error
	for _, ent := range ents {
		devs, err := s.Client.ListDevices(ctx, ent.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ent.Name, err))
			continue
		}
		byPolicy := latestByPolicy(devs)
		for _, m := range ms {
			if !strings.HasPrefix(m.PolicyName, ent.Name+"/") {
				continue
			}
			if err := s.syncOne(ctx, m, byPolicy[m.PolicyName]); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", m.DeviceID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// latestByPolicy はポリシーごとに、いちばん新しく登録された端末を選ぶ。
func latestByPolicy(devs []Device) map[string]*Device {
	sort.SliceStable(devs, func(i, j int) bool { return devs[i].EnrollmentTime < devs[j].EnrollmentTime })
	out := map[string]*Device{}
	for i := range devs {
		d := &devs[i]
		if prev, ok := out[d.PolicyName]; ok && d.State == "DELETED" && prev.State != "DELETED" {
			continue
		}
		out[d.PolicyName] = d
	}
	return out
}

func (s *Service) syncOne(ctx context.Context, m core.Managed, dev *Device) error {
	before := m
	if dev == nil || dev.EnrollmentTokenData != "" && dev.EnrollmentTokenData != m.DeviceID {
		// 端末の側で管理が外れた（AMAPI から消えた）。登録待ちならそのまま待つ。
		if m.ExternalID == "" {
			return nil
		}
		m.State = core.ManagedRemoved
	} else {
		m.ExternalID = dev.Name
		switch dev.State {
		case "ACTIVE", "LOST":
			m.State = core.ManagedActive
		case "DISABLED":
			m.State = core.ManagedDisabled
		case "DELETED":
			m.State = core.ManagedRemoved
		default:
			m.State = core.ManagedPending
		}
		switch dev.ManagementMode {
		case "DEVICE_OWNER":
			m.Mode = ModeFullyManaged
		case "PROFILE_OWNER":
			m.Mode = ModeWorkProfile
		}
		m.Model = strings.TrimSpace(dev.HardwareInfo.Manufacturer + " " + dev.HardwareInfo.Model)
		m.OSVersion = dev.SoftwareInfo.AndroidVersion
		m.SecurityPatch = dev.SoftwareInfo.SecurityPatchLevel
		m.PolicyCompliant = dev.PolicyCompliant
		m.Encrypted = dev.DeviceSettings.IsEncrypted
		m.ScreenLock = dev.DeviceSettings.IsDeviceSecure
		m.Problems = nil
		for _, n := range dev.NonComplianceDetails {
			p := n.SettingName + ": " + n.NonComplianceReason
			if n.PackageName != "" {
				p += " (" + n.PackageName + ")"
			}
			m.Problems = append(m.Problems, p)
		}
		if t, err := time.Parse(time.RFC3339Nano, dev.EnrollmentTime); err == nil {
			m.EnrolledAt = t.UTC()
		}
		if t, err := time.Parse(time.RFC3339Nano, dev.LastStatusReport); err == nil {
			m.ReportedAt = t.UTC()
			if err := s.Store.TouchDevice(ctx, m.DeviceID, m.ReportedAt); err != nil {
				return err
			}
		}
	}
	if sameManaged(before, m) {
		return nil
	}
	return s.Store.PutManaged(ctx, m)
}

func sameManaged(a, b core.Managed) bool {
	return a.ExternalID == b.ExternalID && a.State == b.State && a.Mode == b.Mode && a.Model == b.Model &&
		a.OSVersion == b.OSVersion && a.SecurityPatch == b.SecurityPatch && a.PolicyCompliant == b.PolicyCompliant &&
		a.Encrypted == b.Encrypted && a.ScreenLock == b.ScreenLock && a.EnrolledAt.Equal(b.EnrolledAt) &&
		a.ReportedAt.Equal(b.ReportedAt) && strings.Join(a.Problems, "\n") == strings.Join(b.Problems, "\n")
}

// --- 命令

// 命令の種類。
const (
	CommandLock   = "lock"
	CommandReboot = "reboot"
)

// Command は端末に命令を送る。
func (s *Service) Command(ctx context.Context, d core.Device, typ string) error {
	m, err := s.active(ctx, d)
	if err != nil {
		return err
	}
	var t string
	switch typ {
	case CommandLock:
		t = "LOCK"
	case CommandReboot:
		t = "REBOOT"
	default:
		return fmt.Errorf("android: 知らない命令 %q", typ)
	}
	return s.Client.IssueCommand(ctx, m.ExternalID, Command{Type: t, Duration: "600s"})
}

func (s *Service) active(ctx context.Context, d core.Device) (core.Managed, error) {
	m, err := s.Store.GetManaged(ctx, d.ID)
	if errors.Is(err, core.ErrNotFound) || err == nil && (m.Provider != Provider || m.ExternalID == "" || m.State == core.ManagedRemoved) {
		return m, ErrNotManaged
	}
	return m, err
}

// Managed は端末の管理の状態。無ければ ok が false。
func (s *Service) Managed(ctx context.Context, d core.Device) (core.Managed, bool, error) {
	m, err := s.Store.GetManaged(ctx, d.ID)
	if errors.Is(err, core.ErrNotFound) || err == nil && m.Provider != Provider {
		return m, false, nil
	}
	return m, err == nil, err
}

// Unenroll は端末を管理から外す。完全管理の端末は初期化され、私物の端末は仕事用プロファイルが消える。
func (s *Service) Unenroll(ctx context.Context, d core.Device, reason string) error {
	m, ok, err := s.Managed(ctx, d)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotManaged
	}
	if m.ExternalID != "" && m.State != core.ManagedRemoved {
		if err := s.Client.DeleteDevice(ctx, m.ExternalID, reason); err != nil && !IsNotFound(err) {
			return err
		}
	}
	// 端末が消えるまでポリシーを消せないことがあるので、失敗は記録だけする。
	if err := s.Client.DeletePolicy(ctx, m.PolicyName); err != nil && !IsNotFound(err) {
		s.log().Warn("android delete policy", "policy", m.PolicyName, "err", err)
	}
	return s.Store.DeleteManaged(ctx, d.ID)
}
