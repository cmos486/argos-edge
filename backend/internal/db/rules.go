package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

var (
	ErrRuleNotFound        = errors.New("rule not found")
	ErrRulePriorityTaken   = errors.New("rule priority already taken for this host")
	ErrRuleHostMismatch    = errors.New("rule does not belong to host")
)

const ruleColumns = `id, host_id, priority, name, enabled, action_type,
    action_config, matchers_config, created_at, updated_at`

// ListRulesByHost returns every rule belonging to host_id, ordered by
// priority ASC so the caddycfg layer can iterate in evaluation order.
func ListRulesByHost(ctx context.Context, d *sql.DB, hostID int64) ([]models.Rule, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+ruleColumns+`
		   FROM rules
		  WHERE host_id = ?
		  ORDER BY priority ASC`, hostID)
	if err != nil {
		return nil, fmt.Errorf("query rules: %w", err)
	}
	defer rows.Close()
	var out []models.Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListEnabledRulesByHost is the subset the reconciler iterates.
func ListEnabledRulesByHost(ctx context.Context, d *sql.DB, hostID int64) ([]models.Rule, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+ruleColumns+`
		   FROM rules
		  WHERE host_id = ? AND enabled = 1
		  ORDER BY priority ASC`, hostID)
	if err != nil {
		return nil, fmt.Errorf("query enabled rules: %w", err)
	}
	defer rows.Close()
	var out []models.Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountRulesByHost returns the size of the rule set for a host. Used to
// populate rules_count on GET /api/hosts/{id}.
func CountRulesByHost(ctx context.Context, d *sql.DB, hostID int64) (int, error) {
	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM rules WHERE host_id = ?`, hostID,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("count rules: %w", err)
	}
	return n, nil
}

// CountRulesByHostBatch hydrates rules_count for a whole host slice in
// one query so ListHosts stays O(1) round trips.
func CountRulesByHostBatch(ctx context.Context, d *sql.DB, hostIDs []int64) (map[int64]int, error) {
	out := map[int64]int{}
	if len(hostIDs) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(hostIDs))
	args := make([]any, len(hostIDs))
	for i, id := range hostIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := `SELECT host_id, COUNT(*) FROM rules WHERE host_id IN (` +
		strings.Join(placeholders, ",") + `) GROUP BY host_id`
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("batch count rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hid int64
		var n int
		if err := rows.Scan(&hid, &n); err != nil {
			return nil, err
		}
		out[hid] = n
	}
	return out, rows.Err()
}

// GetRule returns a single rule scoped to host_id. If the rule exists
// but belongs to a different host, returns ErrRuleHostMismatch so the
// handler can surface 404 rather than leak the row's existence.
func GetRule(ctx context.Context, d *sql.DB, hostID, ruleID int64) (models.Rule, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+ruleColumns+`
		   FROM rules WHERE id = ?`, ruleID)
	r, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Rule{}, ErrRuleNotFound
	}
	if err != nil {
		return models.Rule{}, err
	}
	if r.HostID != hostID {
		return models.Rule{}, ErrRuleHostMismatch
	}
	return r, nil
}

// CreateRule inserts a rule. The caller is expected to have validated
// shape (models.Rule.Validate) already. If priority is zero we pick
// max(priority)+10 or 10 when the host has no rules yet.
func CreateRule(ctx context.Context, d *sql.DB, r models.Rule) (models.Rule, error) {
	if r.Priority == 0 {
		next, err := nextPriority(ctx, d, r.HostID)
		if err != nil {
			return models.Rule{}, err
		}
		r.Priority = next
	}
	res, err := d.ExecContext(ctx,
		`INSERT INTO rules
		    (host_id, priority, name, enabled, action_type, action_config, matchers_config)
		 VALUES (?,?,?,?,?,?,?)`,
		r.HostID, r.Priority, r.Name, boolToInt(r.Enabled),
		string(r.Action.Type), marshalOrEmpty(r.Action.Config),
		mustMarshalMatchers(r.Matchers),
	)
	if err != nil {
		if isRulePriorityUnique(err) {
			return models.Rule{}, ErrRulePriorityTaken
		}
		return models.Rule{}, fmt.Errorf("insert rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.Rule{}, fmt.Errorf("last insert id: %w", err)
	}
	return GetRule(ctx, d, r.HostID, id)
}

// UpdateRule overwrites every mutable field of a rule scoped to a host.
func UpdateRule(ctx context.Context, d *sql.DB, r models.Rule) (models.Rule, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE rules
		    SET priority = ?, name = ?, enabled = ?,
		        action_type = ?, action_config = ?, matchers_config = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`,
		r.Priority, r.Name, boolToInt(r.Enabled),
		string(r.Action.Type), marshalOrEmpty(r.Action.Config),
		mustMarshalMatchers(r.Matchers),
		r.ID, r.HostID,
	)
	if err != nil {
		if isRulePriorityUnique(err) {
			return models.Rule{}, ErrRulePriorityTaken
		}
		return models.Rule{}, fmt.Errorf("update rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Rule{}, err
	}
	if n == 0 {
		return models.Rule{}, ErrRuleNotFound
	}
	return GetRule(ctx, d, r.HostID, r.ID)
}

// DeleteRule removes a rule scoped to a host.
func DeleteRule(ctx context.Context, d *sql.DB, hostID, ruleID int64) error {
	res, err := d.ExecContext(ctx,
		`DELETE FROM rules WHERE id = ? AND host_id = ?`, ruleID, hostID)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// ToggleRule flips the enabled flag.
func ToggleRule(ctx context.Context, d *sql.DB, hostID, ruleID int64) (models.Rule, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE rules
		    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`, ruleID, hostID)
	if err != nil {
		return models.Rule{}, fmt.Errorf("toggle rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Rule{}, err
	}
	if n == 0 {
		return models.Rule{}, ErrRuleNotFound
	}
	return GetRule(ctx, d, hostID, ruleID)
}

// ReorderRules reassigns priorities in increments of 10 to the rules
// listed in ruleIDs (first = 10, second = 20, ...). The whole operation
// runs in a transaction; ids not belonging to hostID abort the tx.
//
// To avoid UNIQUE(host_id, priority) collisions while shuffling, the
// first UPDATE nudges each target row into a non-colliding range
// (priority + 100000) and the second UPDATE applies the final value.
func ReorderRules(ctx context.Context, d *sql.DB, hostID int64, ruleIDs []int64) error {
	if len(ruleIDs) == 0 {
		return fmt.Errorf("rule_ids empty")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Confirm all rule ids belong to the host and are exactly the set
	// of rules for it — callers must send the FULL list.
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM rules WHERE host_id = ? ORDER BY id ASC`, hostID)
	if err != nil {
		return fmt.Errorf("list host rules: %w", err)
	}
	existing := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		existing[id] = true
	}
	rows.Close()
	if len(existing) != len(ruleIDs) {
		return fmt.Errorf("reorder expects exactly %d rule ids, got %d", len(existing), len(ruleIDs))
	}
	for _, id := range ruleIDs {
		if !existing[id] {
			return fmt.Errorf("rule id %d does not belong to host %d", id, hostID)
		}
	}

	// Phase 1: move every row to a high-priority parking spot keyed by id
	// (guaranteed unique) so the final assignments cannot collide with
	// the current values.
	for _, id := range ruleIDs {
		if _, err := tx.ExecContext(ctx,
			`UPDATE rules SET priority = id + 100000 WHERE id = ? AND host_id = ?`,
			id, hostID); err != nil {
			return fmt.Errorf("park rule %d: %w", id, err)
		}
	}
	// Phase 2: assign final priorities in increments of 10.
	for i, id := range ruleIDs {
		p := (i + 1) * 10
		if _, err := tx.ExecContext(ctx,
			`UPDATE rules SET priority = ?, updated_at = CURRENT_TIMESTAMP
			  WHERE id = ? AND host_id = ?`,
			p, id, hostID); err != nil {
			return fmt.Errorf("set rule %d priority %d: %w", id, p, err)
		}
	}
	return tx.Commit()
}

// nextPriority returns max(priority) + 10 for the host, or 10 if empty.
func nextPriority(ctx context.Context, d *sql.DB, hostID int64) (int, error) {
	var max sql.NullInt64
	if err := d.QueryRowContext(ctx,
		`SELECT MAX(priority) FROM rules WHERE host_id = ?`, hostID,
	).Scan(&max); err != nil {
		return 0, fmt.Errorf("max priority: %w", err)
	}
	if !max.Valid {
		return 10, nil
	}
	return int(max.Int64) + 10, nil
}

func scanRule(s scanner) (models.Rule, error) {
	var (
		r            models.Rule
		actionType   string
		actionCfg    string
		matchersCfg  string
		enabled      int
	)
	if err := s.Scan(
		&r.ID, &r.HostID, &r.Priority, &r.Name, &enabled,
		&actionType, &actionCfg, &matchersCfg,
		&r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return models.Rule{}, err
	}
	r.Enabled = enabled == 1
	r.Action = models.ActionEnv{
		Type:   models.ActionType(actionType),
		Config: json.RawMessage(actionCfg),
	}
	if matchersCfg != "" {
		if err := json.Unmarshal([]byte(matchersCfg), &r.Matchers); err != nil {
			return models.Rule{}, fmt.Errorf("decode matchers_config: %w", err)
		}
	}
	return r, nil
}

func marshalOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func mustMarshalMatchers(ms []models.MatcherEnv) string {
	if len(ms) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ms)
	if err != nil {
		// Callers have already validated the matchers; a marshal
		// failure here would be a programmer error, not operator input.
		panic(fmt.Sprintf("marshal matchers: %v", err))
	}
	return string(b)
}

func isRulePriorityUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "rules") &&
		strings.Contains(msg, "priority") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}
