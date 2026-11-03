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
