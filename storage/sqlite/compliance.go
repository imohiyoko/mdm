package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// --- 準拠の判定

func scanCompliance(sc interface{ Scan(...any) error }) (core.DeviceCompliance, error) {
	var c core.DeviceCompliance
	var compliant int
	var reasons string
	var changed, evaluated int64
	err := sc.Scan(&c.DeviceID, &compliant, &reasons, &changed, &evaluated)
	c.Compliant, c.ChangedAt, c.EvaluatedAt = compliant == 1, fromMS(changed), fromMS(evaluated)
	c.Reasons = strings.Fields(reasons)
	return c, mapErr(err)
}

func (s *Store) PutCompliance(ctx context.Context, c core.DeviceCompliance) error {
	compliant := 0
	if c.Compliant {
		compliant = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO device_compliance(device_id,compliant,reasons,changed_at,evaluated_at) VALUES(?,?,?,?,?)
	  ON CONFLICT(device_id) DO UPDATE SET compliant=excluded.compliant, reasons=excluded.reasons, changed_at=excluded.changed_at, evaluated_at=excluded.evaluated_at`,
		c.DeviceID, compliant, strings.Join(c.Reasons, " "), ms(c.ChangedAt), ms(c.EvaluatedAt))
	return mapErr(err)
}

const complianceCols = `device_id,compliant,reasons,changed_at,evaluated_at`

func (s *Store) GetCompliance(ctx context.Context, deviceID string) (core.DeviceCompliance, error) {
	return scanCompliance(s.db.QueryRowContext(ctx, `SELECT `+complianceCols+` FROM device_compliance WHERE device_id=?`, deviceID))
}

func (s *Store) ListCompliance(ctx context.Context) ([]core.DeviceCompliance, error) {
	return scanAll(ctx, s.db, scanCompliance, `SELECT `+complianceCols+` FROM device_compliance ORDER BY device_id`)
}

// --- SSF の送る待ち

func scanSSF(sc interface{ Scan(...any) error }) (core.SSFEvent, error) {
	var e core.SSFEvent
	var next, created int64
	err := sc.Scan(&e.ID, &e.Receiver, &e.OrgID, &e.SET, &e.Attempts, &next, &e.LastError, &created)
	e.NextAt, e.CreatedAt = fromMS(next), fromMS(created)
	return e, mapErr(err)
}

func (s *Store) EnqueueSSF(ctx context.Context, events []core.SSFEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range events {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ssf_outbox(receiver,org_id,set_jwt,next_at,created_at) VALUES(?,?,?,?,?)`,
			e.Receiver, e.OrgID, e.SET, ms(e.NextAt), ms(e.CreatedAt)); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit()
}

func (s *Store) DueSSF(ctx context.Context, now time.Time, limit int) ([]core.SSFEvent, error) {
	return scanAll(ctx, s.db, scanSSF, `SELECT id,receiver,org_id,set_jwt,attempts,next_at,last_error,created_at FROM ssf_outbox
	  WHERE next_at<=? ORDER BY id LIMIT ?`, ms(now), limit)
}

func (s *Store) DeleteSSF(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ssf_outbox WHERE id=?`, id)
	return mapErr(err)
}

func (s *Store) RetrySSF(ctx context.Context, id int64, next time.Time, lastError string) error {
	return affected(s.db.ExecContext(ctx, `UPDATE ssf_outbox SET attempts=attempts+1, next_at=?, last_error=? WHERE id=?`, ms(next), lastError, id))
}

func (s *Store) DeleteSSFBefore(ctx context.Context, t time.Time) (int64, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM ssf_outbox WHERE created_at<?`, ms(t))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// --- ネットワークの証明書

func scanNetworkCert(sc interface{ Scan(...any) error }) (core.NetworkCert, error) {
	var c core.NetworkCert
	var notAfter, created int64
	err := sc.Scan(&c.Fingerprint, &c.DeviceID, &notAfter, &created)
	c.NotAfter, c.CreatedAt = fromMS(notAfter), fromMS(created)
	return c, mapErr(err)
}

func (s *Store) PutNetworkCert(ctx context.Context, c core.NetworkCert) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO network_certs(fingerprint,device_id,not_after,created_at) VALUES(?,?,?,?)`,
		c.Fingerprint, c.DeviceID, ms(c.NotAfter), ms(c.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetNetworkCert(ctx context.Context, fingerprint string) (core.NetworkCert, error) {
	return scanNetworkCert(s.db.QueryRowContext(ctx, `SELECT fingerprint,device_id,not_after,created_at FROM network_certs WHERE fingerprint=?`, fingerprint))
}

func (s *Store) ListNetworkCerts(ctx context.Context, deviceID string) ([]core.NetworkCert, error) {
	return scanAll(ctx, s.db, scanNetworkCert, `SELECT fingerprint,device_id,not_after,created_at FROM network_certs WHERE device_id=? ORDER BY created_at`, deviceID)
}

func (s *Store) DeleteNetworkCerts(ctx context.Context, deviceID string) (int64, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM network_certs WHERE device_id=?`, deviceID)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func (s *Store) DeleteNetworkCertsExcept(ctx context.Context, deviceID, keep string) (int64, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM network_certs WHERE device_id=? AND fingerprint<>?`, deviceID, keep)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
