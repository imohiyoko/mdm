package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"

	"github.com/imohiyoko/mdm/core"
)

// --- automations（条件はまとめて JSON で持つ。グループは外部キーで守る）

type automationBody struct {
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Trigger  core.AutomationTrigger `json:"trigger"`
	Windows  []core.Window          `json:"windows,omitempty"`
	TimeZone string                 `json:"time_zone,omitempty"`
	Reasons  []string               `json:"reasons,omitempty"`
}

func encodeAutomation(a core.Automation) (string, error) {
	b, err := json.Marshal(automationBody{a.Enabled, a.Priority, a.Trigger, a.Windows, a.TimeZone, a.Reasons})
	return string(b), err
}

const automationCols = `id,org_id,name,policy_id,body,created_at,updated_at,(SELECT COALESCE(group_concat(group_id, ' '),'') FROM automation_groups WHERE automation_id=automations.id)`

func scanAutomation(sc interface{ Scan(...any) error }) (core.Automation, error) {
	var a core.Automation
	var body, groups string
	var created, updated int64
	if err := sc.Scan(&a.ID, &a.OrgID, &a.Name, &a.PolicyID, &body, &created, &updated, &groups); err != nil {
		return a, mapErr(err)
	}
	var b automationBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return a, err
	}
	a.Enabled, a.Priority, a.Trigger, a.Windows, a.TimeZone, a.Reasons = b.Enabled, b.Priority, b.Trigger, b.Windows, b.TimeZone, b.Reasons
	a.CreatedAt, a.UpdatedAt = fromMS(created), fromMS(updated)
	if groups != "" {
		a.GroupIDs = strings.Fields(groups)
		sort.Strings(a.GroupIDs)
	}
	return a, nil
}

func setAutomationGroups(ctx context.Context, tx *sql.Tx, a core.Automation) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM automation_groups WHERE automation_id=?`, a.ID); err != nil {
		return err
	}
	for _, g := range a.GroupIDs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO automation_groups(automation_id,group_id) VALUES(?,?)`, a.ID, g); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (s *Store) CreateAutomation(ctx context.Context, a core.Automation) error {
	body, err := encodeAutomation(a)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO automations(id,org_id,name,policy_id,body,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		a.ID, a.OrgID, a.Name, a.PolicyID, body, ms(a.CreatedAt), ms(a.UpdatedAt)); err != nil {
		return mapErr(err)
	}
	if err := setAutomationGroups(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetAutomation(ctx context.Context, id string) (core.Automation, error) {
	return scanAutomation(s.db.QueryRowContext(ctx, `SELECT `+automationCols+` FROM automations WHERE id=?`, id))
}

func (s *Store) ListAutomations(ctx context.Context) ([]core.Automation, error) {
	return scanAll(ctx, s.db, scanAutomation, `SELECT `+automationCols+` FROM automations ORDER BY created_at, id`)
}

func (s *Store) UpdateAutomation(ctx context.Context, a core.Automation) error {
	body, err := encodeAutomation(a)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := affected(tx.ExecContext(ctx, `UPDATE automations SET name=?,policy_id=?,body=?,updated_at=? WHERE id=?`,
		a.Name, a.PolicyID, body, ms(a.UpdatedAt), a.ID)); err != nil {
		return err
	}
	if err := setAutomationGroups(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteAutomation(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM automations WHERE id=?`, id))
}
