package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// --- enrollment codes

func (s *Store) PutEnrollmentCode(ctx context.Context, c core.EnrollmentCode) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_codes(hash,device_id,expires_at) VALUES(?,?,?)`, c.Hash, c.DeviceID, ms(c.ExpiresAt))
	return mapErr(err)
}

func (s *Store) GetEnrollmentCode(ctx context.Context, hash []byte) (core.EnrollmentCode, error) {
	var c core.EnrollmentCode
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT hash,device_id,expires_at FROM enrollment_codes WHERE hash=?`, hash).Scan(&c.Hash, &c.DeviceID, &exp)
	c.ExpiresAt = fromMS(exp)
	return c, mapErr(err)
}

func (s *Store) DeleteEnrollmentCodes(ctx context.Context, deviceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM enrollment_codes WHERE device_id=?`, deviceID)
	return err
}

// --- device commands

const commandCols = `id,device_id,verb,loc_uri,format,data,purpose,state,status,result,created_at,sent_at,done_at`

func scanCommand(sc interface{ Scan(...any) error }) (core.DeviceCommand, error) {
	var c core.DeviceCommand
	var state string
	var created, sent, done int64
	err := sc.Scan(&c.ID, &c.DeviceID, &c.Verb, &c.LocURI, &c.Format, &c.Data, &c.Purpose, &state, &c.Status, &c.Result, &created, &sent, &done)
	c.State, c.CreatedAt, c.SentAt, c.DoneAt = core.CommandState(state), fromMS(created), fromMS(sent), fromMS(done)
	return c, mapErr(err)
}

func (s *Store) EnqueueCommands(ctx context.Context, cmds []core.DeviceCommand) ([]core.DeviceCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := make([]core.DeviceCommand, 0, len(cmds))
	for _, c := range cmds {
		c.State = core.CommandPending
		res, err := tx.ExecContext(ctx, `INSERT INTO device_commands(device_id,verb,loc_uri,format,data,purpose,state,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			c.DeviceID, c.Verb, c.LocURI, c.Format, c.Data, c.Purpose, string(c.State), ms(c.CreatedAt))
		if err != nil {
			return nil, mapErr(err)
		}
		if c.ID, err = res.LastInsertId(); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, tx.Commit()
}

func (s *Store) NextCommands(ctx context.Context, deviceID string, resendBefore time.Time, limit int) ([]core.DeviceCommand, error) {
	return scanAll(ctx, s.db, scanCommand, `SELECT `+commandCols+` FROM device_commands
	  WHERE device_id=? AND (state='pending' OR (state='sent' AND sent_at<?)) ORDER BY id LIMIT ?`, deviceID, ms(resendBefore), limit)
}

func (s *Store) MarkCommandsSent(ctx context.Context, ids []int64, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE device_commands SET state='sent', sent_at=? WHERE id=? AND state IN ('pending','sent')`, ms(at), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) FinishCommand(ctx context.Context, deviceID string, id int64, state core.CommandState, status, result string, at time.Time) (core.DeviceCommand, error) {
	// Get は Status と Results の 2 つが返るので、終わったあとに結果だけを足すこともある。
	if _, err := s.db.ExecContext(ctx, `UPDATE device_commands SET state=?, status=CASE WHEN ?='' THEN status ELSE ? END,
	  result=CASE WHEN ?='' THEN result ELSE ? END, done_at=? WHERE id=? AND device_id=?`,
		string(state), status, status, result, result, ms(at), id, deviceID); err != nil {
		return core.DeviceCommand{}, err
	}
	return scanCommand(s.db.QueryRowContext(ctx, `SELECT `+commandCols+` FROM device_commands WHERE id=? AND device_id=?`, id, deviceID))
}

func (s *Store) ListCommands(ctx context.Context, deviceID string, limit int) ([]core.DeviceCommand, error) {
	return scanAll(ctx, s.db, scanCommand, `SELECT `+commandCols+` FROM device_commands WHERE device_id=? ORDER BY id DESC LIMIT ?`, deviceID, limit)
}

func (s *Store) CancelCommands(ctx context.Context, deviceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM device_commands WHERE device_id=? AND state IN ('pending','sent')`, deviceID)
	return err
}

func (s *Store) GetCommand(ctx context.Context, deviceID string, id int64) (core.DeviceCommand, error) {
	return scanCommand(s.db.QueryRowContext(ctx, `SELECT `+commandCols+` FROM device_commands WHERE id=? AND device_id=?`, id, deviceID))
}

func (s *Store) DeleteFinishedCommandsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_commands WHERE state IN ('done','failed') AND done_at<?`, ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) RequeueCommand(ctx context.Context, deviceID string, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE device_commands SET state='pending', sent_at=0 WHERE id=? AND device_id=? AND state='sent'`, id, deviceID)
	return err
}

func (s *Store) ClearCommandData(ctx context.Context, deviceID string, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE device_commands SET data='' WHERE id=? AND device_id=?`, id, deviceID)
	return err
}
