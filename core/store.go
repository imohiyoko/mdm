package core

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound は対象が無い。
var ErrNotFound = errors.New("not found")

// ErrConflict は同じものがすでにある、または参照されていて消せない。
var ErrConflict = errors.New("conflict")

// Store は保存先のポート。
type Store interface {
	CreateOrg(ctx context.Context, o Org) error
	GetOrg(ctx context.Context, id string) (Org, error)
	ListOrgs(ctx context.Context) ([]Org, error)
	UpdateOrg(ctx context.Context, o Org) error
	DeleteOrg(ctx context.Context, id string) error

	CreateGroup(ctx context.Context, g Group) error
	GetGroup(ctx context.Context, id string) (Group, error)
	ListGroups(ctx context.Context) ([]Group, error)
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, id string) error

	CreateAdminBinding(ctx context.Context, b AdminBinding) error
	ListAdminBindings(ctx context.Context) ([]AdminBinding, error)
	// AdminBindingsFor は IAM のユーザーの役割（複数の組織の管理者になれる）。
	AdminBindingsFor(ctx context.Context, issuer, subject string) ([]AdminBinding, error)
	DeleteAdminBinding(ctx context.Context, id string) error

	CreatePerson(ctx context.Context, p Person) error
	GetPerson(ctx context.Context, id string) (Person, error)
	ListPeople(ctx context.Context) ([]Person, error)
	UpdatePerson(ctx context.Context, p Person) error
	DeletePerson(ctx context.Context, id string) error

	CreateDevice(ctx context.Context, d Device) error
	GetDevice(ctx context.Context, id string) (Device, error)
	GetDeviceByTokenHash(ctx context.Context, hash []byte) (Device, error)
	ListDevices(ctx context.Context) ([]Device, error)
	UpdateDevice(ctx context.Context, d Device) error
	TouchDevice(ctx context.Context, id string, at time.Time) error
	DeleteDevice(ctx context.Context, id string) error

	CreatePolicy(ctx context.Context, p Policy) error
	GetPolicy(ctx context.Context, id string) (Policy, error)
	ListPolicies(ctx context.Context) ([]Policy, error)
	UpdatePolicy(ctx context.Context, p Policy) error
	DeletePolicy(ctx context.Context, id string) error

	CreateBlocklist(ctx context.Context, b Blocklist) error
	GetBlocklist(ctx context.Context, id string) (Blocklist, error)
	ListBlocklists(ctx context.Context) ([]Blocklist, error)
	// ReplaceBlocklistDomains は一覧の中身を入れ替え、件数と取り込んだ時刻を記録する。
	ReplaceBlocklistDomains(ctx context.Context, id string, domains []string, at time.Time) error
	SetBlocklistError(ctx context.Context, id string, msg string) error
	BlocklistDomains(ctx context.Context, id string) ([]string, error)
	DeleteBlocklist(ctx context.Context, id string) error

	AppendQueryLogs(ctx context.Context, logs []QueryLog) error
	ListQueryLogs(ctx context.Context, deviceID string, since time.Time, limit int) ([]QueryLog, error)
	DeleteQueryLogsBefore(ctx context.Context, t time.Time) (int64, error)

	// PutManaged は管理の状態を作るか置き換える。
	PutManaged(ctx context.Context, m Managed) error
	GetManaged(ctx context.Context, deviceID string) (Managed, error)
	ListManaged(ctx context.Context, provider string) ([]Managed, error)
	DeleteManaged(ctx context.Context, deviceID string) error

	PutAndroidEnterprise(ctx context.Context, e AndroidEnterprise) error
	GetAndroidEnterprise(ctx context.Context, orgID string) (AndroidEnterprise, error)
	ListAndroidEnterprises(ctx context.Context) ([]AndroidEnterprise, error)
	CreateAndroidSignup(ctx context.Context, s AndroidSignup) error
	// TakeAndroidSignup は申し込みを取り出して消す（1 回しか使えない）。
	TakeAndroidSignup(ctx context.Context, stateHash []byte) (AndroidSignup, error)

	PutEnrollmentCode(ctx context.Context, c EnrollmentCode) error
	GetEnrollmentCode(ctx context.Context, hash []byte) (EnrollmentCode, error)
	// DeleteEnrollmentCodes は端末の合言葉をすべて消す（使い切ったとき・管理を外したとき）。
	DeleteEnrollmentCodes(ctx context.Context, deviceID string) error

	// EnqueueCommands は命令を待ち行列に入れ、ID を付けて返す。
	EnqueueCommands(ctx context.Context, cmds []DeviceCommand) ([]DeviceCommand, error)
	// NextCommands は端末に送る命令（待っているものと、送ったが答えの無いまま resendBefore より前のもの）を古い順に返す。
	NextCommands(ctx context.Context, deviceID string, resendBefore time.Time, limit int) ([]DeviceCommand, error)
	MarkCommandsSent(ctx context.Context, ids []int64, at time.Time) error
	// FinishCommand は端末の答えを記録する。端末のものでなければ ErrNotFound。
	FinishCommand(ctx context.Context, deviceID string, id int64, state CommandState, status, result string, at time.Time) (DeviceCommand, error)
	GetCommand(ctx context.Context, deviceID string, id int64) (DeviceCommand, error)
	ListCommands(ctx context.Context, deviceID string, limit int) ([]DeviceCommand, error)
	// DeleteFinishedCommandsBefore は終わった命令の記録のうち t より前のものを消す。
	DeleteFinishedCommandsBefore(ctx context.Context, t time.Time) (int64, error)

	// PutCompliance は端末の準拠の判定の結果を置く。
	PutCompliance(ctx context.Context, c DeviceCompliance) error
	GetCompliance(ctx context.Context, deviceID string) (DeviceCompliance, error)
	ListCompliance(ctx context.Context) ([]DeviceCompliance, error)

	// PutNetworkCert はネットワークの証明書を覚える。
	PutNetworkCert(ctx context.Context, c NetworkCert) error
	GetNetworkCert(ctx context.Context, fingerprint string) (NetworkCert, error)
	ListNetworkCerts(ctx context.Context, deviceID string) ([]NetworkCert, error)
	// DeleteNetworkCerts は端末のネットワークの証明書をすべて消す（取り消す）。消した数を返す。
	DeleteNetworkCerts(ctx context.Context, deviceID string) (int64, error)
	// DeleteNetworkCertsExcept は端末のネットワークの証明書のうち、指紋が keep のもの以外を消す。
	DeleteNetworkCertsExcept(ctx context.Context, deviceID, keep string) (int64, error)

	// SignupOrg は IAM でログインした人が自分で組織を作る。組織・その人を組織の管理者にする役割・作った人の記録を一度に入れる。
	SignupOrg(ctx context.Context, o Org, admin AdminBinding) error
	// CountSignups はその人が自分で作った組織の数（消した組織は数えない）。
	CountSignups(ctx context.Context, issuer, subject string) (int, error)

	// 組織の管理者への招待。
	CreateInvitation(ctx context.Context, inv Invitation) error
	ListInvitations(ctx context.Context, orgID string) ([]Invitation, error)
	DeleteInvitation(ctx context.Context, orgID, id string) error
	// DeleteExpiredInvitations は期限の過ぎた招待を消す。
	DeleteExpiredInvitations(ctx context.Context, now time.Time) error
	// AcceptInvitation はコードの SHA-256 が codeHash で期限内の招待を消し、admin にその組織と役割を付けて入れる。
	// 招待が無い・期限切れなら ErrNotFound、すでにその組織の管理者なら ErrConflict（招待は残る）。
	AcceptInvitation(ctx context.Context, codeHash []byte, now time.Time, admin AdminBinding) (AdminBinding, error)

	// 組織の管理者が登録したルーターと準拠の知らせの受け手。orgID が空なら、すべての組織のもの。
	CreateRADIUSClient(ctx context.Context, c RADIUSClient) error
	ListRADIUSClients(ctx context.Context, orgID string) ([]RADIUSClient, error)
	DeleteRADIUSClient(ctx context.Context, orgID, id string) error
	CreateSSFReceiver(ctx context.Context, r SSFReceiver) error
	ListSSFReceivers(ctx context.Context, orgID string) ([]SSFReceiver, error)
	DeleteSSFReceiver(ctx context.Context, orgID, id string) error

	// EnqueueSSF は SET を送る待ちに入れる。
	EnqueueSSF(ctx context.Context, events []SSFEvent) error
	// DueSSF は now までに送る SET（古い順に limit 件）。
	DueSSF(ctx context.Context, now time.Time, limit int) ([]SSFEvent, error)
	// DeleteSSF は送り終えた（か、受け手が受けないと答えた）SET を消す。
	DeleteSSF(ctx context.Context, id int64) error
	// RetrySSF は送れなかった SET を next にもう一度送る。
	RetrySSF(ctx context.Context, id int64, next time.Time, lastError string) error
	// DeleteSSFBefore は t より前に作った SET を消す（送れないまま古くなったもの）。
	DeleteSSFBefore(ctx context.Context, t time.Time) (int64, error)
	// RequeueCommand は送った命令を待ちに戻す（端末が今はできないと答えたとき）。
	RequeueCommand(ctx context.Context, deviceID string, id int64) error
	// ClearCommandData は命令の中身を消す（秘密を含む命令を送り終えたとき）。
	ClearCommandData(ctx context.Context, deviceID string, id int64) error
	// CancelCommands は端末の待っている命令を取り消す（管理を外したとき）。
	CancelCommands(ctx context.Context, deviceID string) error

	AppendAudit(ctx context.Context, e AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]AuditEvent, error)

	Close() error
}

// AuditEvent は管理の操作の記録。
type AuditEvent struct {
	At     time.Time
	OrgID  string // 対象の組織。サーバー全体の操作なら空
	Actor  string // 操作した管理者
	Action string // "device.create" など
	Target string // 対象の ID
}

// Clock は時刻の取得のポート。テストでは偽の時計を使う。
type Clock interface{ Now() time.Time }

// SystemClock は実際の時計（UTC）。
type SystemClock struct{}

// Now は現在の UTC の時刻。
func (SystemClock) Now() time.Time { return time.Now().UTC() }
