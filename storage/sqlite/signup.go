package sqlite

import (
	"context"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// --- サインアップ（自分で組織を作る）

func (s *Store) SignupOrg(ctx context.Context, o core.Org, b core.AdminBinding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO orgs(id,name,kind,default_policy_id,created_at) VALUES(?,?,?,?,?)`,
		o.ID, o.Name, string(o.Kind), null(o.DefaultPolicyID), ms(o.CreatedAt)); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_bindings(id,issuer,subject,label,role,org_id,created_at) VALUES(?,?,?,?,?,?,?)`,
		b.ID, b.Issuer, b.Subject, b.Label, string(b.Role), o.ID, ms(b.CreatedAt)); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO org_signups(org_id,issuer,subject,created_at) VALUES(?,?,?,?)`,
		o.ID, b.Issuer, b.Subject, ms(o.CreatedAt)); err != nil {
		return mapErr(err)
	}
	return tx.Commit()
}

func (s *Store) CountSignups(ctx context.Context, issuer, subject string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM org_signups WHERE issuer=? AND subject=?`, issuer, subject).Scan(&n)
	return n, err
}

// --- 招待

const invitationCols = `id,org_id,role,label,code_hash,created_by,expires_at,created_at`

func scanInvitation(sc interface{ Scan(...any) error }) (core.Invitation, error) {
	var inv core.Invitation
	var role string
	var exp, created int64
	err := sc.Scan(&inv.ID, &inv.OrgID, &role, &inv.Label, &inv.CodeHash, &inv.CreatedBy, &exp, &created)
	inv.Role, inv.ExpiresAt, inv.CreatedAt = core.AdminRole(role), fromMS(exp), fromMS(created)
	return inv, mapErr(err)
}

func (s *Store) CreateInvitation(ctx context.Context, inv core.Invitation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO invitations(`+invitationCols+`) VALUES(?,?,?,?,?,?,?,?)`,
		inv.ID, inv.OrgID, string(inv.Role), inv.Label, inv.CodeHash, inv.CreatedBy, ms(inv.ExpiresAt), ms(inv.CreatedAt))
	return mapErr(err)
}

func (s *Store) ListInvitations(ctx context.Context, orgID string) ([]core.Invitation, error) {
	return scanAll(ctx, s.db, scanInvitation, `SELECT `+invitationCols+` FROM invitations WHERE org_id=? ORDER BY created_at, id`, orgID)
}

func (s *Store) DeleteInvitation(ctx context.Context, orgID, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM invitations WHERE id=? AND org_id=?`, id, orgID))
}

func (s *Store) DeleteExpiredInvitations(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM invitations WHERE expires_at<=?`, ms(now))
	return mapErr(err)
}

func (s *Store) AcceptInvitation(ctx context.Context, codeHash []byte, now time.Time, b core.AdminBinding) (core.AdminBinding, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	// 先に消して、同じコードを同時に使っても 1 回だけ受かるようにする。
	inv, err := scanInvitation(tx.QueryRowContext(ctx, `DELETE FROM invitations WHERE code_hash=? AND expires_at>? RETURNING `+invitationCols, codeHash, ms(now)))
	if err != nil {
		return b, err // 無い・期限切れは core.ErrNotFound
	}
	b.OrgID, b.Role = inv.OrgID, inv.Role
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_bindings(id,issuer,subject,label,role,org_id,created_at) VALUES(?,?,?,?,?,?,?)`,
		b.ID, b.Issuer, b.Subject, b.Label, string(b.Role), b.OrgID, ms(b.CreatedAt)); err != nil {
		return b, mapErr(err)
	}
	return b, tx.Commit()
}

// --- 組織の iPhone・Mac の通知用の証明書

func (s *Store) GetApplePush(ctx context.Context, orgID string) (core.ApplePush, error) {
	var p core.ApplePush
	var exp, upd int64
	err := s.db.QueryRowContext(ctx, `SELECT org_id,topic,cert_pem,key_pem,not_after,pending_key_pem,updated_at FROM apple_push WHERE org_id=?`, orgID).
		Scan(&p.OrgID, &p.Topic, &p.CertPEM, &p.KeyPEM, &exp, &p.PendingKeyPEM, &upd)
	p.NotAfter, p.UpdatedAt = fromMS(exp), fromMS(upd)
	return p, mapErr(err)
}

func (s *Store) PutApplePush(ctx context.Context, p core.ApplePush) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO apple_push(org_id,topic,cert_pem,key_pem,not_after,pending_key_pem,updated_at) VALUES(?,?,?,?,?,?,?)
	  ON CONFLICT(org_id) DO UPDATE SET topic=excluded.topic,cert_pem=excluded.cert_pem,key_pem=excluded.key_pem,
	  not_after=excluded.not_after,pending_key_pem=excluded.pending_key_pem,updated_at=excluded.updated_at`,
		p.OrgID, p.Topic, p.CertPEM, p.KeyPEM, ms(p.NotAfter), p.PendingKeyPEM, ms(p.UpdatedAt))
	return mapErr(err)
}

func (s *Store) DeleteApplePush(ctx context.Context, orgID string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM apple_push WHERE org_id=?`, orgID))
}
