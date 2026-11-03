// Package core は端末管理の中心のデータとポートを定義する。アダプタ（保存先・上流の DNS など）を import しない。
package core

import (
	"net/netip"
	"time"
)

// Role は家族（管理の単位）の中での立場。
type Role string

const (
	RoleChild Role = "child" // 管理される側
	RoleAdult Role = "adult" // 管理される側だが、制限は緩くするのが普通
)

// Platform は端末の種類。
type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformOther   Platform = "other"
)

// Valid は既知の種類か。
func (p Platform) Valid() bool {
	switch p {
	case PlatformIOS, PlatformAndroid, PlatformWindows, PlatformMacOS, PlatformOther:
		return true
	}
	return false
}

// OrgKind は組織の種類。できることは同じで、管理画面の言葉づかいと既定のルールが変わる。
type OrgKind string

const (
	OrgFamily  OrgKind = "family"
	OrgCompany OrgKind = "company"
)

// Org は管理の単位（家族・会社）。人・端末・グループ・ポリシーはどれか 1 つの組織に属する。
type Org struct {
	ID              string
	Name            string
	Kind            OrgKind
	DefaultPolicyID string // 空ならサーバー全体の既定のポリシー
	CreatedAt       time.Time
}

// Group は組織の中のまとまり（部署・兄弟など）。人は複数のグループに入れる。
type Group struct {
	ID       string
	OrgID    string
	Name     string
	PolicyID string // 空ならポリシーを決めない
	// Priority は、人が複数のグループに入っているとき、どのグループのポリシーを使うか。大きいほうが勝つ。
	Priority  int
	CreatedAt time.Time
}

// Person は端末を使う人。
type Person struct {
	ID       string
	OrgID    string
	Name     string
	Role     Role
	PolicyID string   // 空ならグループ、それも無ければ組織の既定のポリシー
	GroupIDs []string // 入っているグループ
	// Email は IAM での利用者のメールアドレス。端末の準拠の状態を IAM に知らせるときに、利用者を示すのに使う。
	Email     string
	CreatedAt time.Time
}

// AdminRole は管理者の役割。
type AdminRole string

const (
	// AdminServer はサーバー全体の管理者。組織・管理者・取り込む一覧を管理できる。
	AdminServer AdminRole = "server_admin"
	// AdminOrg は 1 つの組織の管理者。その組織の中のすべてを管理できる。
	AdminOrg AdminRole = "org_admin"
	// AdminOrgViewer は 1 つの組織を見るだけ（記録の確認など）。
	AdminOrgViewer AdminRole = "org_viewer"
)

// Valid は既知の役割か。
func (r AdminRole) Valid() bool {
	return r == AdminServer || r == AdminOrg || r == AdminOrgViewer
}

// AdminBinding は IAM のユーザーに管理者の役割を与える。
type AdminBinding struct {
	ID        string
	Issuer    string // IAM の issuer
	Subject   string // IAM の sub
	Label     string // 表示用（メールアドレスなど）
	Role      AdminRole
	OrgID     string // server_admin なら空
	CreatedAt time.Time
}

// Device は管理する端末。
type Device struct {
	ID       string
	OrgID    string
	Name     string
	Platform Platform
	PersonID string // 空なら持ち主なし（共用の端末）
	PolicyID string // 空なら持ち主のポリシー、それも空なら既定のポリシー
	// FilterTokenHash は DoH で端末を見分ける秘密の SHA-256。秘密そのものは保存しない。
	FilterTokenHash []byte
	// DoTLabelHash は DoT のホスト名の先頭のラベルの SHA-256。
	// TLS のホスト名（SNI）は暗号化されずに流れるので、DoH の秘密とは別の値にする（ADR 0002）。
	DoTLabelHash []byte
	// PausedUntil より前は、許可リスト以外の通信をすべて止める（「今すぐ止める」）。
	PausedUntil time.Time
	CreatedAt   time.Time
	LastSeenAt  time.Time
}

// FilterMode は通信フィルターの基本の動き。
type FilterMode string

const (
	// FilterBlocklist はブロックの一覧に当たる通信だけを止める。
	FilterBlocklist FilterMode = "blocklist"
	// FilterAllowlistOnly は許可の一覧に当たる通信だけを通す（小さな子ども向け）。
	FilterAllowlistOnly FilterMode = "allowlist_only"
)

// Policy は端末に配るルール。通信フィルター・端末の制限・アプリのルール。
type Policy struct {
	ID       string
	OrgID    string // 空ならサーバー全体のポリシー（既定のポリシー）。どの組織からも使える
	Name     string
	Mode     FilterMode
	Allow    []string // ドメイン。サブドメインも含む。ブロックより優先する
	Block    []string // ドメイン。サブドメインも含む
	ListIDs  []string // 使うブロックの一覧（外部の一覧を取り込んだもの）
	Quiet    []Window // この時間帯は許可の一覧以外を止める（夜など）
	TimeZone string   // Quiet の時刻の解釈に使う IANA の名前。空なら UTC
	// LogQueries が false なら、問い合わせの記録を残さない（止めたものの記録は残す）。
	LogQueries bool
	// Device は端末そのものの制限。MDM で管理している端末に効く（いまは Android）。
	Device DeviceRules
	// AndroidApps は Android のアプリのルール。
	AndroidApps AppRules
	// WindowsApps は Windows のアプリのルール。いまは Blocked（Microsoft Store のアプリのパッケージ名）だけを使う。
	WindowsApps AppRules
	// AppleApps は iPhone・iPad・Mac のアプリのルール（バンドル ID）。Blocked と、Mode が allowlist のときの Allowed を使う。監視モードの端末だけで効く。
	AppleApps AppRules
	// Compliance は端末が会社などのルールに沿っているか（準拠）の判定の条件。
	Compliance ComplianceRules
	// WiFi は端末の証明書で入る Wi-Fi（WPA2・WPA3 Enterprise、EAP-TLS）。MDM が設定と証明書を端末に配る。
	WiFi      []WiFiNetwork
	UpdatedAt time.Time
}

// WiFiNetwork は証明書で入る Wi-Fi のネットワーク。
type WiFiNetwork struct {
	SSID string
	// Hidden は名前を知らせないネットワーク（端末から探しに行く）。
	Hidden bool
}

// ComplianceRules は準拠の判定の条件。MDM で管理していて、ポリシーを受け入れていることはいつも求める。
type ComplianceRules struct {
	RequireEncryption bool // 保存したデータの暗号化
	RequireScreenLock bool // 画面ロック（パスコード）
	// MaxReportAgeHours 時間より長く端末から報告が無ければ準拠していない。0 なら見ない。
	MaxReportAgeHours int
	// MinOSVersion は OS の最低の版（機種ごと。"android"・"ios"・"macos"・"windows"）。例 "17.4"。
	MinOSVersion map[Platform]string
}

// DeviceCompliance は端末の準拠の判定の結果。
type DeviceCompliance struct {
	DeviceID  string
	Compliant bool
	// Reasons は準拠していない理由（not_managed・policy_not_applied・not_encrypted・no_screen_lock・os_outdated・not_reporting）。
	Reasons []string
	// ChangedAt は準拠しているかが変わった時刻。
	ChangedAt   time.Time
	EvaluatedAt time.Time
}

// SSFEvent は IAM などに送る Security Event Token（SSF）の送る待ち。
type SSFEvent struct {
	ID        int64
	Receiver  string // 設定の受け手の名前
	OrgID     string // 端末の組織。送るときに受け手の組織の制限をもう一度確かめる
	SET       string // 署名した SET
	Attempts  int
	NextAt    time.Time
	LastError string
	CreatedAt time.Time
}

// DeviceRules は端末そのものの制限。OS ごとにできることが違うので、できない OS では無視する。
type DeviceRules struct {
	CameraDisabled        bool // カメラを使えなくする
	ScreenCaptureDisabled bool // 画面の撮影を禁止する
	// FactoryResetDisabled は設定からの初期化を禁止する（子どもが管理を外せないように）。完全管理の端末だけ。
	FactoryResetDisabled bool
	// VPNConfigDisabled は VPN の設定を禁止する（VPN で通信フィルターを避けられないように）。
	VPNConfigDisabled bool
	// PasscodeMinLength が 1 以上なら、その桁数以上の画面ロックを必須にする。
	PasscodeMinLength int
}

// AppMode はアプリのルールの基本の動き。
type AppMode string

const (
	// AppsOpen は禁止したアプリ以外を入れられる。
	AppsOpen AppMode = "open"
	// AppsAllowlist は許可したアプリだけを入れられる（ほかは消える）。
	AppsAllowlist AppMode = "allowlist"
)

// AppRules はアプリの許可・禁止・自動で入れるもの。アプリはパッケージ名（com.example.app）で書く。
type AppRules struct {
	Mode     AppMode
	Required []string // 自動で入れて、消せなくする
	Allowed  []string // 入れてよい（Mode が allowlist のとき意味がある）
	Blocked  []string // 入れられない。入っていれば消える
}

// Window は曜日と時刻の範囲。End が Start より前なら日をまたぐ（22:00〜07:00）。
type Window struct {
	Days  []time.Weekday // 空なら毎日。日をまたぐときは始まった日の曜日で判定する
	Start TimeOfDay
	End   TimeOfDay
}

// TimeOfDay は 0 時からの分（0〜1439）。
type TimeOfDay int

// Contains は t（その時間帯のタイムゾーンでの時刻）がこの時間帯に入るか。
func (w Window) Contains(t time.Time) bool {
	m := TimeOfDay(t.Hour()*60 + t.Minute())
	if w.Start == w.End {
		return false
	}
	if w.Start < w.End {
		return m >= w.Start && m < w.End && w.onDay(t.Weekday())
	}
	// 日をまたぐ。始まった日の曜日で判定する。
	if m >= w.Start {
		return w.onDay(t.Weekday())
	}
	if m < w.End {
		return w.onDay((t.Weekday() + 6) % 7)
	}
	return false
}

func (w Window) onDay(d time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, x := range w.Days {
		if x == d {
			return true
		}
	}
	return false
}

// Blocklist は外部の一覧（hosts 形式・ドメインの一覧）を取り込んだもの。
type Blocklist struct {
	ID          string
	Name        string
	URL         string
	Domains     int // 取り込んだドメインの数
	RefreshedAt time.Time
	LastError   string
}

// Action は通信フィルターの判定。
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// QueryLog は通信フィルターの記録。
type QueryLog struct {
	DeviceID string
	At       time.Time
	Name     string
	Type     string
	Action   Action
	Reason   string
}

// Managed は MDM で管理している端末の状態。端末ごとに 1 つ。
type Managed struct {
	DeviceID string
	Provider string // "android"・"windows"・"apple"
	// ExternalID は管理の仕組みの側の端末の名前（enterprises/…/devices/…）。登録が済むまで空。
	ExternalID string
	// PolicyName は管理の仕組みの側のポリシーの名前（Android は端末ごとに 1 つ）。
	PolicyName string
	State      ManagedState
	Mode       string // "fully_managed"（会社・家の端末）か "work_profile"（私物の中の仕事用）
	Model      string
	OSVersion  string
	// SecurityPatch は "2026-10-01" など。
	SecurityPatch string
	// PolicyCompliant は端末がポリシーを守れていると報告したか。Problems にその理由。
	PolicyCompliant bool
	Problems        []string
	Encrypted       bool
	ScreenLock      bool
	// PolicyHash は最後に配ったポリシーの要約。同じなら配り直さない。
	PolicyHash string
	// CertFingerprints は端末の証明書の SHA-256（16 進）。新しいものが先。Windows のように証明書で端末を確かめる機種だけ。
	CertFingerprints []string `json:",omitempty"`
	// InventoryAt は最後に端末の情報（OS の版など）を問い合わせた時刻。
	InventoryAt time.Time `json:",omitempty"`
	// PushToken と PushMagic は端末を起こす通知（Apple の APNs）に使う。
	PushToken string `json:",omitempty"`
	PushMagic string `json:",omitempty"`
	// Supervised は監視モードの端末か（Apple）。強い制限は監視モードでだけ効く。
	Supervised bool `json:",omitempty"`
	// FilterManaged は通信フィルターを MDM で端末に配っているか（Apple の監視モードの端末）。
	FilterManaged bool `json:",omitempty"`
	// WiFiHash は最後に配った Wi-Fi の設定の要約。WiFiCert はそのときの端末の証明書の指紋。
	WiFiHash string `json:",omitempty"`
	WiFiCert string `json:",omitempty"`
	// WiFiSSIDs は配った Wi-Fi の名前（Windows で、無くなったものを消すのに使う）。
	WiFiSSIDs  []string `json:",omitempty"`
	EnrolledAt time.Time
	ReportedAt time.Time
}

// ManagedState は管理の状態。
type ManagedState string

const (
	ManagedPending  ManagedState = "pending"  // 登録の QR コードを出した。端末の登録を待っている
	ManagedActive   ManagedState = "active"   // 管理している
	ManagedDisabled ManagedState = "disabled" // 管理の仕組みの側で止められている
	ManagedRemoved  ManagedState = "removed"  // 端末の側で管理が外れた（初期化・仕事用プロファイルの削除）
	// ManagedUnenrolling は管理を外す命令を送るところ（端末が次に通信してきたときに外れる）。
	ManagedUnenrolling ManagedState = "unenrolling"
)

// AndroidEnterprise は組織の Android の管理の単位（Google の enterprise）。組織ごとに 1 つ。
type AndroidEnterprise struct {
	OrgID     string
	Name      string // enterprises/LC0…
	CreatedAt time.Time
}

// AndroidSignup は Google の登録の画面から戻ってくるのを待っている申し込み。
type AndroidSignup struct {
	StateHash     []byte // 戻り先の URL に付ける秘密の SHA-256
	OrgID         string
	SignupURLName string // signupUrls/…
	ExpiresAt     time.Time
}

// EnrollmentCode は端末の登録に使う 1 回だけの合言葉（Windows の登録のパスワード）。平文は保存しない。
type EnrollmentCode struct {
	Hash      []byte
	DeviceID  string
	ExpiresAt time.Time
}

// DeviceCommand は端末に送る命令（Windows の OMA-DM のコマンド）。端末が次に通信してきたときに送る。
type DeviceCommand struct {
	ID       int64
	DeviceID string
	Verb     string // "Get"・"Replace"・"Exec"・"Delete"・"Add"
	LocURI   string
	Format   string // "int"・"chr"・"bool"・"xml" など。空なら付けない
	Data     string
	// Purpose は命令の目的（"policy"・"inventory"・"reboot" など）。結果の扱いに使う。
	Purpose   string
	State     CommandState
	Status    string // 端末が返した状態のコード（"200" など）
	Result    string // Get の結果
	CreatedAt time.Time
	SentAt    time.Time
	DoneAt    time.Time
}

// CommandState は命令の状態。
type CommandState string

const (
	CommandPending CommandState = "pending"
	CommandSent    CommandState = "sent"
	CommandDone    CommandState = "done"
	CommandFailed  CommandState = "failed"
)

// RADIUSClient は組織の管理者が登録したルーター（Wi-Fi のアクセスポイント）。その組織の端末だけを入れる。
type RADIUSClient struct {
	ID        string
	OrgID     string
	Name      string
	Prefix    netip.Prefix // 問い合わせてくるアドレス（グローバルの IP か小さい範囲）
	Secret    string       // 共有の秘密。RADIUS の確かめに元の値が要るので、そのまま持つ
	CreatedAt time.Time
}

// SSFReceiver は組織の管理者が登録した、準拠の知らせの受け手（その組織の IAM）。
type SSFReceiver struct {
	ID        string
	OrgID     string
	Name      string
	URL       string
	PushToken string
	Audience  string
	CreatedAt time.Time
}

// NetworkCert は Wi-Fi などのネットワークに入るために端末に発行した証明書。消すと、その証明書では入れなくなる。
type NetworkCert struct {
	Fingerprint string // SHA-256（16 進の小文字）
	DeviceID    string
	NotAfter    time.Time
	CreatedAt   time.Time
}
