// Package core は端末管理の中心のデータとポートを定義する。アダプタ（保存先・上流の DNS など）を import しない。
package core

import "time"

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
	ID        string
	OrgID     string
	Name      string
	Role      Role
	PolicyID  string   // 空ならグループ、それも無ければ組織の既定のポリシー
	GroupIDs  []string // 入っているグループ
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

// Policy は端末に配るルール。いまは通信フィルターの分だけを持つ。
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
	UpdatedAt  time.Time
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
