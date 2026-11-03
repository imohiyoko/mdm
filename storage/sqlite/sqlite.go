// Package sqlite は core.Store の SQLite のアダプタ。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  org_id TEXT REFERENCES orgs(id),
  name TEXT NOT NULL,
  body TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  default_policy_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_groups (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id),
  name TEXT NOT NULL,
  policy_id TEXT REFERENCES policies(id),
  priority INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_bindings (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  org_id TEXT REFERENCES orgs(id),
  created_at INTEGER NOT NULL,
  UNIQUE (issuer, subject, org_id)
);
CREATE TABLE IF NOT EXISTS people (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id),
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  policy_id TEXT REFERENCES policies(id),
  email TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS person_groups (
  person_id TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES org_groups(id),
  PRIMARY KEY (person_id, group_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  person_id TEXT REFERENCES people(id),
  policy_id TEXT REFERENCES policies(id),
  filter_token_hash BLOB NOT NULL UNIQUE,
  dot_label_hash BLOB NOT NULL UNIQUE,
  paused_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS blocklists (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  domains INTEGER NOT NULL DEFAULT 0,
  refreshed_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blocklist_domains (
  list_id TEXT NOT NULL REFERENCES blocklists(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  PRIMARY KEY (list_id, domain)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS query_logs (
  device_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  name TEXT NOT NULL,
  qtype TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS query_logs_device_at ON query_logs(device_id, at);
CREATE INDEX IF NOT EXISTS query_logs_at ON query_logs(at);
CREATE TABLE IF NOT EXISTS managed (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  external_id TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS managed_provider ON managed(provider);
CREATE TABLE IF NOT EXISTS android_enterprises (
  org_id TEXT PRIMARY KEY REFERENCES orgs(id),
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS android_signups (
  state_hash BLOB PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  signup_url_name TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_codes (
  hash BLOB PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  verb TEXT NOT NULL,
  loc_uri TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  sent_at INTEGER NOT NULL DEFAULT 0,
  done_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS device_commands_device ON device_commands(device_id, state, id);
CREATE TABLE IF NOT EXISTS device_compliance (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  compliant INTEGER NOT NULL,
  reasons TEXT NOT NULL,
  changed_at INTEGER NOT NULL,
  evaluated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS network_certs (
  fingerprint TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  not_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS network_certs_device ON network_certs(device_id);
CREATE TABLE IF NOT EXISTS radius_clients (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  prefix TEXT UNIQUE,
  secret TEXT NOT NULL,
  cert_fingerprint TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ssf_receivers (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  push_token TEXT NOT NULL,
  audience TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_signups (
  org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS org_signups_user ON org_signups(issuer, subject);
CREATE TABLE IF NOT EXISTS invitations (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  label TEXT NOT NULL,
  code_hash BLOB NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS apple_push (
  org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  topic TEXT NOT NULL,
  cert_pem TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  not_after INTEGER NOT NULL,
  pending_key_pem TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_limits (
  org_id TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
  devices INTEGER NOT NULL,
  people INTEGER NOT NULL,
  groups_ INTEGER NOT NULL,
  policies INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ssf_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receiver TEXT NOT NULL,
  org_id TEXT NOT NULL DEFAULT '',
  set_jwt TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ssf_outbox_next ON ssf_outbox(next_at);
CREATE TABLE IF NOT EXISTS audit (
  at INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL
);
`

// Store は SQLite に保存する。
type Store struct{ db *sql.DB }

var _ core.Store = (*Store)(nil)

// Open は path の SQLite を開き、表を作る。":memory:" はテスト用。
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1) // メモリの DB は接続ごとに別になる
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close は閉じる。
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return core.ErrNotFound
	}
	if err != nil && (strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "FOREIGN KEY constraint") || strings.Contains(err.Error(), "PRIMARY KEY")) {
		return fmt.Errorf("%w: %v", core.ErrConflict, err)
	}
	return err
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// --- people

func setPersonGroups(ctx context.Context, tx *sql.Tx, p core.Person) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM person_groups WHERE person_id=?`, p.ID); err != nil {
		return err
	}
	for _, g := range p.GroupIDs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO person_groups(person_id,group_id) VALUES(?,?)`, p.ID, g); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (s *Store) CreatePerson(ctx context.Context, p core.Person) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO people(id,org_id,name,role,policy_id,email,created_at) VALUES(?,?,?,?,?,?,?)`,
		p.ID, p.OrgID, p.Name, string(p.Role), null(p.PolicyID), p.Email, ms(p.CreatedAt)); err != nil {
		return mapErr(err)
	}
	if err := setPersonGroups(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit()
}

const personCols = `id,org_id,name,role,COALESCE(policy_id,''),email,created_at,(SELECT COALESCE(group_concat(group_id, ' '),'') FROM person_groups WHERE person_id=people.id)`

func scanPerson(sc interface{ Scan(...any) error }) (core.Person, error) {
	var p core.Person
	var role, groups string
	var created int64
	err := sc.Scan(&p.ID, &p.OrgID, &p.Name, &role, &p.PolicyID, &p.Email, &created, &groups)
	p.Role, p.CreatedAt = core.Role(role), fromMS(created)
	if groups != "" {
		p.GroupIDs = strings.Fields(groups)
		sort.Strings(p.GroupIDs)
	}
	return p, mapErr(err)
}

func (s *Store) GetPerson(ctx context.Context, id string) (core.Person, error) {
	return scanPerson(s.db.QueryRowContext(ctx, `SELECT `+personCols+` FROM people WHERE id=?`, id))
}

func (s *Store) ListPeople(ctx context.Context) ([]core.Person, error) {
	return scanAll(ctx, s.db, scanPerson, `SELECT `+personCols+` FROM people ORDER BY created_at, id`)
}

func (s *Store) UpdatePerson(ctx context.Context, p core.Person) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := affected(tx.ExecContext(ctx, `UPDATE people SET name=?,role=?,policy_id=?,email=? WHERE id=?`,
		p.Name, string(p.Role), null(p.PolicyID), p.Email, p.ID)); err != nil {
		return err
	}
	if err := setPersonGroups(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit()
}

// scanAll は行をすべて読む。
func scanAll[T any](ctx context.Context, db *sql.DB, scan func(interface{ Scan(...any) error }) (T, error), q string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// --- orgs

const orgCols = `id,name,kind,COALESCE(default_policy_id,''),created_at`

func scanOrg(sc interface{ Scan(...any) error }) (core.Org, error) {
	var o core.Org
	var kind string
	var created int64
	err := sc.Scan(&o.ID, &o.Name, &kind, &o.DefaultPolicyID, &created)
	o.Kind, o.CreatedAt = core.OrgKind(kind), fromMS(created)
	return o, mapErr(err)
}

func (s *Store) CreateOrg(ctx context.Context, o core.Org) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO orgs(id,name,kind,default_policy_id,created_at) VALUES(?,?,?,?,?)`,
		o.ID, o.Name, string(o.Kind), null(o.DefaultPolicyID), ms(o.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetOrg(ctx context.Context, id string) (core.Org, error) {
	return scanOrg(s.db.QueryRowContext(ctx, `SELECT `+orgCols+` FROM orgs WHERE id=?`, id))
}

func (s *Store) ListOrgs(ctx context.Context) ([]core.Org, error) {
	return scanAll(ctx, s.db, scanOrg, `SELECT `+orgCols+` FROM orgs ORDER BY created_at, id`)
}

func (s *Store) UpdateOrg(ctx context.Context, o core.Org) error {
	return affected(s.db.ExecContext(ctx, `UPDATE orgs SET name=?,kind=?,default_policy_id=? WHERE id=?`, o.Name, string(o.Kind), null(o.DefaultPolicyID), o.ID))
}

// DeleteOrg は空の組織だけを消す（人・端末・グループ・ポリシー・管理者が残っていれば core.ErrConflict）。
func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT
	  (SELECT count(*) FROM people WHERE org_id=?) + (SELECT count(*) FROM devices WHERE org_id=?) +
	  (SELECT count(*) FROM org_groups WHERE org_id=?) + (SELECT count(*) FROM policies WHERE org_id=?) +
	  (SELECT count(*) FROM admin_bindings WHERE org_id=?) + (SELECT count(*) FROM android_enterprises WHERE org_id=?)`, id, id, id, id, id, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: org is not empty", core.ErrConflict)
	}
	return affected(s.db.ExecContext(ctx, `DELETE FROM orgs WHERE id=?`, id))
}

// --- groups

const groupCols = `id,org_id,name,COALESCE(policy_id,''),priority,created_at`

func scanGroup(sc interface{ Scan(...any) error }) (core.Group, error) {
	var g core.Group
	var created int64
	err := sc.Scan(&g.ID, &g.OrgID, &g.Name, &g.PolicyID, &g.Priority, &created)
	g.CreatedAt = fromMS(created)
	return g, mapErr(err)
}

func (s *Store) CreateGroup(ctx context.Context, g core.Group) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO org_groups(id,org_id,name,policy_id,priority,created_at) VALUES(?,?,?,?,?,?)`,
		g.ID, g.OrgID, g.Name, null(g.PolicyID), g.Priority, ms(g.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetGroup(ctx context.Context, id string) (core.Group, error) {
	return scanGroup(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM org_groups WHERE id=?`, id))
}

func (s *Store) ListGroups(ctx context.Context) ([]core.Group, error) {
	return scanAll(ctx, s.db, scanGroup, `SELECT `+groupCols+` FROM org_groups ORDER BY created_at, id`)
}

func (s *Store) UpdateGroup(ctx context.Context, g core.Group) error {
	return affected(s.db.ExecContext(ctx, `UPDATE org_groups SET name=?,policy_id=?,priority=? WHERE id=?`, g.Name, null(g.PolicyID), g.Priority, g.ID))
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM org_groups WHERE id=?`, id))
}

// --- admin bindings

const bindingCols = `id,issuer,subject,label,role,COALESCE(org_id,''),created_at`

func scanBinding(sc interface{ Scan(...any) error }) (core.AdminBinding, error) {
	var b core.AdminBinding
	var role string
	var created int64
	err := sc.Scan(&b.ID, &b.Issuer, &b.Subject, &b.Label, &role, &b.OrgID, &created)
	b.Role, b.CreatedAt = core.AdminRole(role), fromMS(created)
	return b, mapErr(err)
}

func (s *Store) CreateAdminBinding(ctx context.Context, b core.AdminBinding) error {
	// UNIQUE は NULL どうしを同じと見ないので、サーバー全体の管理者の重なりはここで確かめる。
	if b.OrgID == "" {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_bindings WHERE issuer=? AND subject=? AND org_id IS NULL`, b.Issuer, b.Subject).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: duplicate admin binding", core.ErrConflict)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_bindings(id,issuer,subject,label,role,org_id,created_at) VALUES(?,?,?,?,?,?,?)`,
		b.ID, b.Issuer, b.Subject, b.Label, string(b.Role), null(b.OrgID), ms(b.CreatedAt))
	return mapErr(err)
}

func (s *Store) ListAdminBindings(ctx context.Context) ([]core.AdminBinding, error) {
	return scanAll(ctx, s.db, scanBinding, `SELECT `+bindingCols+` FROM admin_bindings ORDER BY created_at, id`)
}

func (s *Store) AdminBindingsFor(ctx context.Context, issuer, subject string) ([]core.AdminBinding, error) {
	return scanAll(ctx, s.db, scanBinding, `SELECT `+bindingCols+` FROM admin_bindings WHERE issuer=? AND subject=? ORDER BY id`, issuer, subject)
}

func (s *Store) DeleteAdminBinding(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM admin_bindings WHERE id=?`, id))
}

func (s *Store) DeletePerson(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM people WHERE id=?`, id))
}

// --- devices

const deviceCols = `id,org_id,name,platform,COALESCE(person_id,''),COALESCE(policy_id,''),filter_token_hash,dot_label_hash,paused_until,created_at,last_seen_at`

func scanDevice(sc interface{ Scan(...any) error }) (core.Device, error) {
	var d core.Device
	var platform string
	var paused, created, seen int64
	err := sc.Scan(&d.ID, &d.OrgID, &d.Name, &platform, &d.PersonID, &d.PolicyID, &d.FilterTokenHash, &d.DoTLabelHash, &paused, &created, &seen)
	d.Platform, d.PausedUntil, d.CreatedAt, d.LastSeenAt = core.Platform(platform), fromMS(paused), fromMS(created), fromMS(seen)
	return d, mapErr(err)
}

func (s *Store) CreateDevice(ctx context.Context, d core.Device) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices(id,org_id,name,platform,person_id,policy_id,filter_token_hash,dot_label_hash,paused_until,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		d.ID, d.OrgID, d.Name, string(d.Platform), null(d.PersonID), null(d.PolicyID), d.FilterTokenHash, d.DoTLabelHash, ms(d.PausedUntil), ms(d.CreatedAt), ms(d.LastSeenAt))
	return mapErr(err)
}

func (s *Store) GetDevice(ctx context.Context, id string) (core.Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id=?`, id))
}

func (s *Store) GetDeviceByTokenHash(ctx context.Context, hash []byte) (core.Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE filter_token_hash=?`, hash))
}

func (s *Store) ListDevices(ctx context.Context) ([]core.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) UpdateDevice(ctx context.Context, d core.Device) error {
	return affected(s.db.ExecContext(ctx, `UPDATE devices SET name=?,platform=?,person_id=?,policy_id=?,filter_token_hash=?,dot_label_hash=?,paused_until=? WHERE id=?`,
		d.Name, string(d.Platform), null(d.PersonID), null(d.PolicyID), d.FilterTokenHash, d.DoTLabelHash, ms(d.PausedUntil), d.ID))
}

func (s *Store) TouchDevice(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at=? WHERE id=? AND last_seen_at<?`, ms(at), id, ms(at))
	return err
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id))
}

// --- policies（一覧や時間帯はまとめて JSON で持つ）

type policyBody struct {
	Mode       core.FilterMode      `json:"mode"`
	Allow      []string             `json:"allow,omitempty"`
	Block      []string             `json:"block,omitempty"`
	ListIDs    []string             `json:"list_ids,omitempty"`
	Quiet      []core.Window        `json:"quiet,omitempty"`
	TimeZone   string               `json:"time_zone,omitempty"`
	LogQueries bool                 `json:"log_queries"`
	Device     core.DeviceRules     `json:"device"`
	Android    core.AppRules        `json:"android_apps"`
	Windows    core.AppRules        `json:"windows_apps"`
	Apple      core.AppRules        `json:"apple_apps"`
	Compliance core.ComplianceRules `json:"compliance"`
	WiFi       []core.WiFiNetwork   `json:"wifi,omitempty"`
}

func encodePolicy(p core.Policy) (string, error) {
	b, err := json.Marshal(policyBody{p.Mode, p.Allow, p.Block, p.ListIDs, p.Quiet, p.TimeZone, p.LogQueries, p.Device, p.AndroidApps, p.WindowsApps, p.AppleApps, p.Compliance, p.WiFi})
	return string(b), err
}

func scanPolicy(sc interface{ Scan(...any) error }) (core.Policy, error) {
	var p core.Policy
	var body string
	var updated int64
	if err := sc.Scan(&p.ID, &p.OrgID, &p.Name, &body, &updated); err != nil {
		return p, mapErr(err)
	}
	var b policyBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return p, err
	}
	p.Mode, p.Allow, p.Block, p.ListIDs, p.Quiet, p.TimeZone, p.LogQueries = b.Mode, b.Allow, b.Block, b.ListIDs, b.Quiet, b.TimeZone, b.LogQueries
	p.Device, p.AndroidApps, p.WindowsApps, p.AppleApps, p.Compliance, p.WiFi = b.Device, b.Android, b.Windows, b.Apple, b.Compliance, b.WiFi
	p.UpdatedAt = fromMS(updated)
	return p, nil
}

func (s *Store) CreatePolicy(ctx context.Context, p core.Policy) error {
	body, err := encodePolicy(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO policies(id,org_id,name,body,updated_at) VALUES(?,?,?,?,?)`, p.ID, null(p.OrgID), p.Name, body, ms(p.UpdatedAt))
	return mapErr(err)
}

func (s *Store) GetPolicy(ctx context.Context, id string) (core.Policy, error) {
	return scanPolicy(s.db.QueryRowContext(ctx, `SELECT id,COALESCE(org_id,''),name,body,updated_at FROM policies WHERE id=?`, id))
}

func (s *Store) ListPolicies(ctx context.Context) ([]core.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,COALESCE(org_id,''),name,body,updated_at FROM policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePolicy(ctx context.Context, p core.Policy) error {
	body, err := encodePolicy(p)
	if err != nil {
		return err
	}
	return affected(s.db.ExecContext(ctx, `UPDATE policies SET name=?,body=?,updated_at=? WHERE id=?`, p.Name, body, ms(p.UpdatedAt), p.ID))
}

func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id))
}

// --- blocklists

const blocklistCols = `id,name,url,domains,refreshed_at,last_error`

func scanBlocklist(sc interface{ Scan(...any) error }) (core.Blocklist, error) {
	var b core.Blocklist
	var refreshed int64
	err := sc.Scan(&b.ID, &b.Name, &b.URL, &b.Domains, &refreshed, &b.LastError)
	b.RefreshedAt = fromMS(refreshed)
	return b, mapErr(err)
}

func (s *Store) CreateBlocklist(ctx context.Context, b core.Blocklist) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO blocklists(id,name,url) VALUES(?,?,?)`, b.ID, b.Name, b.URL)
	return mapErr(err)
}

func (s *Store) GetBlocklist(ctx context.Context, id string) (core.Blocklist, error) {
	return scanBlocklist(s.db.QueryRowContext(ctx, `SELECT `+blocklistCols+` FROM blocklists WHERE id=?`, id))
}

func (s *Store) ListBlocklists(ctx context.Context) ([]core.Blocklist, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+blocklistCols+` FROM blocklists ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Blocklist
	for rows.Next() {
		b, err := scanBlocklist(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceBlocklistDomains(ctx context.Context, id string, domains []string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := affected(tx.ExecContext(ctx, `UPDATE blocklists SET domains=?,refreshed_at=?,last_error='' WHERE id=?`, len(domains), ms(at), id)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_domains WHERE list_id=?`, id); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO blocklist_domains(list_id,domain) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, d := range domains {
		if _, err := stmt.ExecContext(ctx, id, d); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetBlocklistError(ctx context.Context, id string, msg string) error {
	return affected(s.db.ExecContext(ctx, `UPDATE blocklists SET last_error=? WHERE id=?`, msg, id))
}

func (s *Store) BlocklistDomains(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM blocklist_domains WHERE list_id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBlocklist(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM blocklists WHERE id=?`, id))
}

// --- query logs

func (s *Store) AppendQueryLogs(ctx context.Context, logs []core.QueryLog) error {
	if len(logs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO query_logs(device_id,at,name,qtype,action,reason) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, l := range logs {
		if _, err := stmt.ExecContext(ctx, l.DeviceID, ms(l.At), l.Name, l.Type, string(l.Action), l.Reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListQueryLogs(ctx context.Context, deviceID string, since time.Time, limit int) ([]core.QueryLog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id,at,name,qtype,action,reason FROM query_logs WHERE device_id=? AND at>=? ORDER BY at DESC LIMIT ?`,
		deviceID, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.QueryLog
	for rows.Next() {
		var l core.QueryLog
		var at int64
		var action string
		if err := rows.Scan(&l.DeviceID, &at, &l.Name, &l.Type, &action, &l.Reason); err != nil {
			return nil, err
		}
		l.At, l.Action = fromMS(at), core.Action(action)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) DeleteQueryLogsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM query_logs WHERE at<?`, ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- audit

func (s *Store) AppendAudit(ctx context.Context, e core.AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit(at,org_id,actor,action,target) VALUES(?,?,?,?,?)`, ms(e.At), e.OrgID, e.Actor, e.Action, e.Target)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]core.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at,org_id,actor,action,target FROM audit ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.AuditEvent
	for rows.Next() {
		var e core.AuditEvent
		var at int64
		if err := rows.Scan(&at, &e.OrgID, &e.Actor, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		e.At = fromMS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
