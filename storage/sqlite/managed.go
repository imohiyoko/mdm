package sqlite

import (
	"context"
	"encoding/json"

	"github.com/imohiyoko/mdm/core"
)

// --- managed（管理の状態は OS ごとに項目が増えるので JSON で持つ）

func scanManaged(sc interface{ Scan(...any) error }) (core.Managed, error) {
	var m core.Managed
	var body string
	if err := sc.Scan(&body); err != nil {
		return m, mapErr(err)
	}
	err := json.Unmarshal([]byte(body), &m)
	return m, err
}

func (s *Store) PutManaged(ctx context.Context, m core.Managed) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO managed(device_id,provider,external_id,body) VALUES(?,?,?,?)
	  ON CONFLICT(device_id) DO UPDATE SET provider=excluded.provider, external_id=excluded.external_id, body=excluded.body`,
		m.DeviceID, m.Provider, m.ExternalID, string(b))
	return mapErr(err)
}

func (s *Store) GetManaged(ctx context.Context, deviceID string) (core.Managed, error) {
	return scanManaged(s.db.QueryRowContext(ctx, `SELECT body FROM managed WHERE device_id=?`, deviceID))
}

func (s *Store) ListManaged(ctx context.Context, provider string) ([]core.Managed, error) {
	return scanAll(ctx, s.db, scanManaged, `SELECT body FROM managed WHERE provider=? ORDER BY device_id`, provider)
}

func (s *Store) DeleteManaged(ctx context.Context, deviceID string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM managed WHERE device_id=?`, deviceID))
}

// --- android

func scanEnterprise(sc interface{ Scan(...any) error }) (core.AndroidEnterprise, error) {
	var e core.AndroidEnterprise
	var created int64
	err := sc.Scan(&e.OrgID, &e.Name, &created)
	e.CreatedAt = fromMS(created)
	return e, mapErr(err)
}

func (s *Store) PutAndroidEnterprise(ctx context.Context, e core.AndroidEnterprise) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO android_enterprises(org_id,name,created_at) VALUES(?,?,?)
	  ON CONFLICT(org_id) DO UPDATE SET name=excluded.name, created_at=excluded.created_at`, e.OrgID, e.Name, ms(e.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetAndroidEnterprise(ctx context.Context, orgID string) (core.AndroidEnterprise, error) {
	return scanEnterprise(s.db.QueryRowContext(ctx, `SELECT org_id,name,created_at FROM android_enterprises WHERE org_id=?`, orgID))
}

func (s *Store) ListAndroidEnterprises(ctx context.Context) ([]core.AndroidEnterprise, error) {
	return scanAll(ctx, s.db, scanEnterprise, `SELECT org_id,name,created_at FROM android_enterprises ORDER BY org_id`)
}

func (s *Store) CreateAndroidSignup(ctx context.Context, a core.AndroidSignup) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO android_signups(state_hash,org_id,signup_url_name,expires_at) VALUES(?,?,?,?)`,
		a.StateHash, a.OrgID, a.SignupURLName, ms(a.ExpiresAt))
	return mapErr(err)
}

func (s *Store) TakeAndroidSignup(ctx context.Context, stateHash []byte) (core.AndroidSignup, error) {
	var a core.AndroidSignup
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM android_signups WHERE state_hash=? RETURNING state_hash,org_id,signup_url_name,expires_at`, stateHash).
		Scan(&a.StateHash, &a.OrgID, &a.SignupURLName, &exp)
	a.ExpiresAt = fromMS(exp)
	return a, mapErr(err)
}
