// Package sqlite は core.Store の SQLite のアダプタ。
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  body TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS people (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  policy_id TEXT REFERENCES policies(id),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  person_id TEXT REFERENCES people(id),
  policy_id TEXT REFERENCES policies(id),
  filter_token_hash BLOB NOT NULL UNIQUE,
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
CREATE TABLE IF NOT EXISTS audit (
  at INTEGER NOT NULL,
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

func (s *Store) CreatePerson(ctx context.Context, p core.Person) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO people(id,name,role,policy_id,created_at) VALUES(?,?,?,?,?)`,
		p.ID, p.Name, string(p.Role), null(p.PolicyID), ms(p.CreatedAt))
	return mapErr(err)
}

const personCols = `id,name,role,COALESCE(policy_id,''),created_at`

func scanPerson(sc interface{ Scan(...any) error }) (core.Person, error) {
	var p core.Person
	var role string
	var created int64
	err := sc.Scan(&p.ID, &p.Name, &role, &p.PolicyID, &created)
	p.Role, p.CreatedAt = core.Role(role), fromMS(created)
	return p, mapErr(err)
}

func (s *Store) GetPerson(ctx context.Context, id string) (core.Person, error) {
	return scanPerson(s.db.QueryRowContext(ctx, `SELECT `+personCols+` FROM people WHERE id=?`, id))
}

func (s *Store) ListPeople(ctx context.Context) ([]core.Person, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+personCols+` FROM people ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Person
	for rows.Next() {
		p, err := scanPerson(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePerson(ctx context.Context, p core.Person) error {
	return affected(s.db.ExecContext(ctx, `UPDATE people SET name=?,role=?,policy_id=? WHERE id=?`,
		p.Name, string(p.Role), null(p.PolicyID), p.ID))
}

func (s *Store) DeletePerson(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM people WHERE id=?`, id))
}

// --- devices

const deviceCols = `id,name,platform,COALESCE(person_id,''),COALESCE(policy_id,''),filter_token_hash,paused_until,created_at,last_seen_at`

func scanDevice(sc interface{ Scan(...any) error }) (core.Device, error) {
	var d core.Device
	var platform string
	var paused, created, seen int64
	err := sc.Scan(&d.ID, &d.Name, &platform, &d.PersonID, &d.PolicyID, &d.FilterTokenHash, &paused, &created, &seen)
	d.Platform, d.PausedUntil, d.CreatedAt, d.LastSeenAt = core.Platform(platform), fromMS(paused), fromMS(created), fromMS(seen)
	return d, mapErr(err)
}

func (s *Store) CreateDevice(ctx context.Context, d core.Device) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices(id,name,platform,person_id,policy_id,filter_token_hash,paused_until,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		d.ID, d.Name, string(d.Platform), null(d.PersonID), null(d.PolicyID), d.FilterTokenHash, ms(d.PausedUntil), ms(d.CreatedAt), ms(d.LastSeenAt))
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
	return affected(s.db.ExecContext(ctx, `UPDATE devices SET name=?,platform=?,person_id=?,policy_id=?,filter_token_hash=?,paused_until=? WHERE id=?`,
		d.Name, string(d.Platform), null(d.PersonID), null(d.PolicyID), d.FilterTokenHash, ms(d.PausedUntil), d.ID))
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
	Mode       core.FilterMode `json:"mode"`
	Allow      []string        `json:"allow,omitempty"`
	Block      []string        `json:"block,omitempty"`
	ListIDs    []string        `json:"list_ids,omitempty"`
	Quiet      []core.Window   `json:"quiet,omitempty"`
	TimeZone   string          `json:"time_zone,omitempty"`
	LogQueries bool            `json:"log_queries"`
}

func encodePolicy(p core.Policy) (string, error) {
	b, err := json.Marshal(policyBody{p.Mode, p.Allow, p.Block, p.ListIDs, p.Quiet, p.TimeZone, p.LogQueries})
	return string(b), err
}

func scanPolicy(sc interface{ Scan(...any) error }) (core.Policy, error) {
	var p core.Policy
	var body string
	var updated int64
	if err := sc.Scan(&p.ID, &p.Name, &body, &updated); err != nil {
		return p, mapErr(err)
	}
	var b policyBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return p, err
	}
	p.Mode, p.Allow, p.Block, p.ListIDs, p.Quiet, p.TimeZone, p.LogQueries = b.Mode, b.Allow, b.Block, b.ListIDs, b.Quiet, b.TimeZone, b.LogQueries
	p.UpdatedAt = fromMS(updated)
	return p, nil
}

func (s *Store) CreatePolicy(ctx context.Context, p core.Policy) error {
	body, err := encodePolicy(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO policies(id,name,body,updated_at) VALUES(?,?,?,?)`, p.ID, p.Name, body, ms(p.UpdatedAt))
	return mapErr(err)
}

func (s *Store) GetPolicy(ctx context.Context, id string) (core.Policy, error) {
	return scanPolicy(s.db.QueryRowContext(ctx, `SELECT id,name,body,updated_at FROM policies WHERE id=?`, id))
}

func (s *Store) ListPolicies(ctx context.Context) ([]core.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,body,updated_at FROM policies ORDER BY id`)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)`, ms(e.At), e.Actor, e.Action, e.Target)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]core.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at,actor,action,target FROM audit ORDER BY at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.AuditEvent
	for rows.Next() {
		var e core.AuditEvent
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		e.At = fromMS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
