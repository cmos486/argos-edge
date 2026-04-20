package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
)

// ErrChannelNotFound / ErrRuleNotFound are returned when a lookup by
// id misses. Callers turn these into 404s.
var (
	ErrChannelNotFound      = errors.New("notification channel not found")
	ErrRuleNotFound         = errors.New("notification rule not found")
	ErrDeliveryNotFound     = errors.New("notification delivery not found")
	ErrSubscriptionNotFound = errors.New("push subscription not found")
)

// NotifRepo wraps the *sql.DB + the crypto cipher so CRUD methods can
// transparently encrypt/decrypt secret fields in the channel config
// JSON.
type NotifRepo struct {
	DB     *sql.DB
	Cipher *crypto.Cipher
}

// secretFields returns the set of config keys that must be encrypted
// before hitting the DB for a given channel type. The map is small so
// a linear check is cheaper than a second data structure.
func secretFields(ct ChannelType) []string {
	switch ct {
	case TypeWebhook:
		return []string{"headers"}
	case TypeEmail:
		return []string{"smtp_password"}
	case TypeTelegram:
		return []string{"bot_token"}
	}
	return nil
}

// encryptConfig takes a cleartext config map and replaces every secret
// field with the argos-encrypted ciphertext, handling the UNCHANGED
// sentinel (meaning "leave the previously stored value alone").
func (r *NotifRepo) encryptConfig(ct ChannelType, incoming, previous map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(incoming))
	for k, v := range incoming {
		out[k] = v
	}
	for _, f := range secretFields(ct) {
		raw, ok := out[f]
		if !ok {
			// field missing entirely -> treat as UNCHANGED
			if prev, pok := previous[f]; pok {
				out[f] = prev
			}
			continue
		}
		// UNCHANGED sentinel: keep previous ciphertext
		if s, isStr := raw.(string); isStr && s == crypto.Unchanged {
			if prev, pok := previous[f]; pok {
				out[f] = prev
			} else {
				delete(out, f)
			}
			continue
		}
		// non-string values (e.g. webhook headers is a map) get JSON-
		// serialised before encryption so we can round-trip them.
		var plaintext string
		if s, isStr := raw.(string); isStr {
			plaintext = s
		} else {
			b, err := json.Marshal(raw)
			if err != nil {
				return nil, fmt.Errorf("marshal secret %q: %w", f, err)
			}
			plaintext = string(b)
		}
		if plaintext == "" {
			out[f] = ""
			continue
		}
		enc, err := r.Cipher.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt %q: %w", f, err)
		}
		out[f] = enc
	}
	return out, nil
}

// decryptConfig expands ciphertexts back to their original types (e.g.
// unwrapping the JSON inside an encrypted webhook.headers blob).
// Intended for the sender path, NOT for API responses.
func (r *NotifRepo) decryptConfig(ct ChannelType, cfg map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	for _, f := range secretFields(ct) {
		raw, ok := out[f]
		if !ok {
			continue
		}
		s, isStr := raw.(string)
		if !isStr || s == "" {
			continue
		}
		if !crypto.IsEncrypted(s) {
			// plaintext (shouldn't happen for persisted rows, but be
			// defensive for tests + edge cases)
			continue
		}
		pt, err := r.Cipher.Decrypt(s)
		if err != nil {
			return nil, fmt.Errorf("decrypt %q: %w", f, err)
		}
		// try to JSON-unmarshal back into its original shape; on
		// failure, keep it as string
		var any any
		if err := json.Unmarshal([]byte(pt), &any); err == nil {
			out[f] = any
		} else {
			out[f] = pt
		}
	}
	return out, nil
}

// redactConfig masks every secret field in the config for API output.
// Uses the argos1: prefix probe so we can tell "secret is set but
// hidden" apart from "secret is empty".
func redactConfig(ct ChannelType, cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	for _, f := range secretFields(ct) {
		raw, ok := out[f]
		if !ok {
			continue
		}
		s, isStr := raw.(string)
		switch {
		case isStr && s == "":
			out[f] = ""
		case isStr && crypto.IsEncrypted(s):
			out[f] = crypto.Unchanged
		default:
			// anything else is a real value; still redact
			out[f] = crypto.Unchanged
		}
	}
	return out
}

// ListChannels returns every channel with secrets redacted for API use.
func (r *NotifRepo) ListChannels(ctx context.Context, redact bool) ([]Channel, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT id, name, type, enabled, config, template,
		       rate_limit_per_minute, created_at, updated_at
		FROM notification_channels
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		ch, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		if redact {
			ch.Config = redactConfig(ch.Type, ch.Config)
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// GetChannel fetches one channel.
//   - redact=true -> for API output (secrets masked)
//   - redact=false -> for sender (secrets decrypted to plaintext)
func (r *NotifRepo) GetChannel(ctx context.Context, id int64, redact bool) (*Channel, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, name, type, enabled, config, template,
		       rate_limit_per_minute, created_at, updated_at
		FROM notification_channels WHERE id = ?`, id)
	ch, err := scanChannel(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrChannelNotFound
		}
		return nil, err
	}
	if redact {
		ch.Config = redactConfig(ch.Type, ch.Config)
	} else {
		// decrypt for sender
		cfg, err := r.decryptConfig(ch.Type, ch.Config)
		if err != nil {
			return nil, err
		}
		ch.Config = cfg
	}
	return &ch, nil
}

// rawChannelConfig fetches the on-disk config (ciphertexts intact)
// without any decryption. Used during update to merge UNCHANGED
// fields with the previous value.
func (r *NotifRepo) rawChannelConfig(ctx context.Context, id int64) (map[string]any, ChannelType, error) {
	row := r.DB.QueryRowContext(ctx, `SELECT type, config FROM notification_channels WHERE id = ?`, id)
	var typ string
	var cfgStr string
	if err := row.Scan(&typ, &cfgStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrChannelNotFound
		}
		return nil, "", err
	}
	var cfg map[string]any
	if cfgStr != "" {
		if err := json.Unmarshal([]byte(cfgStr), &cfg); err != nil {
			return nil, "", fmt.Errorf("decode prev config: %w", err)
		}
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, ChannelType(typ), nil
}

// CreateChannel persists a new channel, encrypting secret fields.
func (r *NotifRepo) CreateChannel(ctx context.Context, in *Channel) (*Channel, error) {
	enc, err := r.encryptConfig(in.Type, in.Config, nil)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(enc)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	res, err := r.DB.ExecContext(ctx, `
		INSERT INTO notification_channels
		  (name, type, enabled, config, template, rate_limit_per_minute)
		VALUES (?, ?, ?, ?, ?, ?)`,
		in.Name, string(in.Type), in.Enabled, string(b), in.Template, in.RateLimitPerMinute)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return r.GetChannel(ctx, id, true)
}

// UpdateChannel rewrites a channel; UNCHANGED sentinels in the config
// preserve the existing ciphertext per-field.
func (r *NotifRepo) UpdateChannel(ctx context.Context, id int64, in *Channel) (*Channel, error) {
	prev, prevType, err := r.rawChannelConfig(ctx, id)
	if err != nil {
		return nil, err
	}
	// Disallow changing the channel type on update; mixing secret shapes
	// would invalidate previous ciphertexts.
	if in.Type != "" && in.Type != prevType {
		return nil, fmt.Errorf("channel type is immutable (was %s, got %s)", prevType, in.Type)
	}
	in.Type = prevType
	enc, err := r.encryptConfig(prevType, in.Config, prev)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(enc)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if _, err := r.DB.ExecContext(ctx, `
		UPDATE notification_channels
		   SET name = ?, enabled = ?, config = ?, template = ?,
		       rate_limit_per_minute = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		in.Name, in.Enabled, string(b), in.Template, in.RateLimitPerMinute, id); err != nil {
		return nil, err
	}
	return r.GetChannel(ctx, id, true)
}

// DeleteChannel removes a channel (cascades to its rules).
func (r *NotifRepo) DeleteChannel(ctx context.Context, id int64) error {
	res, err := r.DB.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrChannelNotFound
	}
	return nil
}

// ToggleChannel flips enabled.
func (r *NotifRepo) ToggleChannel(ctx context.Context, id int64) (*Channel, error) {
	if _, err := r.DB.ExecContext(ctx,
		`UPDATE notification_channels SET enabled = NOT enabled,
		 updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return r.GetChannel(ctx, id, true)
}

// scanChannel handles both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanChannel(s scanner) (Channel, error) {
	var (
		ch      Channel
		typ     string
		cfgStr  string
		tmplStr sql.NullString
	)
	if err := s.Scan(&ch.ID, &ch.Name, &typ, &ch.Enabled, &cfgStr, &tmplStr,
		&ch.RateLimitPerMinute, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
		return ch, err
	}
	ch.Type = ChannelType(typ)
	ch.Template = tmplStr.String
	if cfgStr == "" {
		ch.Config = map[string]any{}
	} else {
		if err := json.Unmarshal([]byte(cfgStr), &ch.Config); err != nil {
			return ch, fmt.Errorf("decode config: %w", err)
		}
	}
	return ch, nil
}

// --- Rules ---

func (r *NotifRepo) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT id, name, channel_id, event_type, filter_host_ids, filter_severities,
		       enabled, throttle_window_seconds, created_at, updated_at
		FROM notification_rules
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		ru, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ru)
	}
	return out, rows.Err()
}

// ActiveRulesFor returns enabled rules matching an event type, for the
// hot path in the worker. Filters (host / severity) are evaluated in
// Go so we don't need a clever SQL expression on TEXT JSON columns.
func (r *NotifRepo) ActiveRulesFor(ctx context.Context, et EventType) ([]Rule, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT id, name, channel_id, event_type, filter_host_ids, filter_severities,
		       enabled, throttle_window_seconds, created_at, updated_at
		FROM notification_rules
		WHERE enabled = 1 AND event_type = ?`, string(et))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		ru, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ru)
	}
	return out, rows.Err()
}

func (r *NotifRepo) GetRule(ctx context.Context, id int64) (*Rule, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, name, channel_id, event_type, filter_host_ids, filter_severities,
		       enabled, throttle_window_seconds, created_at, updated_at
		FROM notification_rules WHERE id = ?`, id)
	ru, err := scanRule(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRuleNotFound
		}
		return nil, err
	}
	return &ru, nil
}

func (r *NotifRepo) CreateRule(ctx context.Context, in *Rule) (*Rule, error) {
	hostJSON := marshalInt64Slice(in.FilterHostIDs)
	sevJSON := marshalSeveritySlice(in.FilterSeverities)
	res, err := r.DB.ExecContext(ctx, `
		INSERT INTO notification_rules
		  (name, channel_id, event_type, filter_host_ids, filter_severities,
		   enabled, throttle_window_seconds)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.ChannelID, string(in.EventType), hostJSON, sevJSON,
		in.Enabled, in.ThrottleWindowSeconds)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return r.GetRule(ctx, id)
}

func (r *NotifRepo) UpdateRule(ctx context.Context, id int64, in *Rule) (*Rule, error) {
	hostJSON := marshalInt64Slice(in.FilterHostIDs)
	sevJSON := marshalSeveritySlice(in.FilterSeverities)
	res, err := r.DB.ExecContext(ctx, `
		UPDATE notification_rules
		   SET name = ?, channel_id = ?, event_type = ?, filter_host_ids = ?,
		       filter_severities = ?, enabled = ?, throttle_window_seconds = ?,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		in.Name, in.ChannelID, string(in.EventType), hostJSON, sevJSON,
		in.Enabled, in.ThrottleWindowSeconds, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrRuleNotFound
	}
	return r.GetRule(ctx, id)
}

func (r *NotifRepo) DeleteRule(ctx context.Context, id int64) error {
	res, err := r.DB.ExecContext(ctx, `DELETE FROM notification_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRuleNotFound
	}
	return nil
}

func (r *NotifRepo) ToggleRule(ctx context.Context, id int64) (*Rule, error) {
	if _, err := r.DB.ExecContext(ctx,
		`UPDATE notification_rules SET enabled = NOT enabled,
		 updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return r.GetRule(ctx, id)
}

func scanRule(s scanner) (Rule, error) {
	var (
		ru       Rule
		evType   string
		hostJSON string
		sevJSON  string
	)
	if err := s.Scan(&ru.ID, &ru.Name, &ru.ChannelID, &evType, &hostJSON, &sevJSON,
		&ru.Enabled, &ru.ThrottleWindowSeconds, &ru.CreatedAt, &ru.UpdatedAt); err != nil {
		return ru, err
	}
	ru.EventType = EventType(evType)
	ru.FilterHostIDs = unmarshalInt64Slice(hostJSON)
	ru.FilterSeverities = unmarshalSeveritySlice(sevJSON)
	return ru, nil
}

func marshalInt64Slice(v []int64) string {
	if len(v) == 0 {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func unmarshalInt64Slice(s string) []int64 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var v []int64
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

func marshalSeveritySlice(v []Severity) string {
	if len(v) == 0 {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func unmarshalSeveritySlice(s string) []Severity {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var v []Severity
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

// --- Deliveries ---

// DeliveryFilter bounds a list query.
type DeliveryFilter struct {
	ChannelID *int64
	RuleID    *int64
	EventType string
	Status    string
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

func (r *NotifRepo) InsertDelivery(ctx context.Context, d *Delivery) (int64, error) {
	res, err := r.DB.ExecContext(ctx, `
		INSERT INTO notification_deliveries
		  (rule_id, channel_id, event_type, event_payload, rendered_payload,
		   status, error_message, attempts, sent_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullInt64(d.RuleID), nullInt64(d.ChannelID),
		string(d.EventType), d.EventPayload, d.RenderedPayload,
		string(d.Status), d.ErrorMessage, d.Attempts, nullTime(d.SentAt))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *NotifRepo) UpdateDelivery(ctx context.Context, d *Delivery) error {
	_, err := r.DB.ExecContext(ctx, `
		UPDATE notification_deliveries
		   SET rendered_payload = ?, status = ?, error_message = ?,
		       attempts = ?, sent_at = ?
		 WHERE id = ?`,
		d.RenderedPayload, string(d.Status), d.ErrorMessage, d.Attempts,
		nullTime(d.SentAt), d.ID)
	return err
}

func (r *NotifRepo) GetDelivery(ctx context.Context, id int64) (*Delivery, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, rule_id, channel_id, event_type, event_payload, rendered_payload,
		       status, error_message, attempts, created_at, sent_at
		FROM notification_deliveries WHERE id = ?`, id)
	d, err := scanDelivery(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeliveryNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (r *NotifRepo) ListDeliveries(ctx context.Context, f DeliveryFilter) ([]Delivery, error) {
	q := strings.Builder{}
	q.WriteString(`SELECT id, rule_id, channel_id, event_type, event_payload, rendered_payload,
		status, error_message, attempts, created_at, sent_at
		FROM notification_deliveries WHERE 1=1 `)
	var args []any
	if f.ChannelID != nil {
		q.WriteString(` AND channel_id = ?`)
		args = append(args, *f.ChannelID)
	}
	if f.RuleID != nil {
		q.WriteString(` AND rule_id = ?`)
		args = append(args, *f.RuleID)
	}
	if f.EventType != "" {
		q.WriteString(` AND event_type = ?`)
		args = append(args, f.EventType)
	}
	if f.Status != "" {
		q.WriteString(` AND status = ?`)
		args = append(args, f.Status)
	}
	if f.From != nil {
		q.WriteString(` AND created_at >= ?`)
		args = append(args, f.From.UTC())
	}
	if f.To != nil {
		q.WriteString(` AND created_at <= ?`)
		args = append(args, f.To.UTC())
	}
	q.WriteString(` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`)
	lim := f.Limit
	if lim <= 0 || lim > 1000 {
		lim = 200
	}
	args = append(args, lim, f.Offset)

	rows, err := r.DB.QueryContext(ctx, q.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeliveryStats counts sent/failed/throttled/rate_limited rows in a
// time range. Used by the stats cards in the history tab.
func (r *NotifRepo) DeliveryStats(ctx context.Context, from, to time.Time) (map[string]int, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT status, COUNT(*) FROM notification_deliveries
		WHERE created_at >= ? AND created_at <= ?
		GROUP BY status`, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// RecentAlerts returns the last N critical/error deliveries (any status)
// for the Dashboard widget.
func (r *NotifRepo) RecentAlerts(ctx context.Context, limit int, since time.Time) ([]Delivery, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := r.DB.QueryContext(ctx, `
		SELECT d.id, d.rule_id, d.channel_id, d.event_type, d.event_payload,
		       d.rendered_payload, d.status, d.error_message, d.attempts,
		       d.created_at, d.sent_at
		FROM notification_deliveries d
		WHERE d.created_at >= ?
		  AND (d.event_payload LIKE '%"severity":"critical"%'
		       OR d.event_payload LIKE '%"severity":"error"%')
		ORDER BY d.created_at DESC
		LIMIT ?`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PurgeDeliveries drops deliveries older than cutoff AND keeps at most
// keepMax rows by created_at. Returns number deleted.
func (r *NotifRepo) PurgeDeliveries(ctx context.Context, cutoff time.Time, keepMax int) (int64, error) {
	var total int64
	if res, err := r.DB.ExecContext(ctx,
		`DELETE FROM notification_deliveries WHERE created_at < ?`, cutoff.UTC()); err == nil {
		n, _ := res.RowsAffected()
		total += n
	} else {
		return total, err
	}
	if keepMax > 0 {
		if res, err := r.DB.ExecContext(ctx, `
			DELETE FROM notification_deliveries
			 WHERE id IN (
			   SELECT id FROM notification_deliveries
			    ORDER BY created_at DESC
			    LIMIT -1 OFFSET ?
			 )`, keepMax); err == nil {
			n, _ := res.RowsAffected()
			total += n
		} else {
			return total, err
		}
	}
	return total, nil
}

func scanDelivery(s scanner) (Delivery, error) {
	var (
		d        Delivery
		ruleID   sql.NullInt64
		chID     sql.NullInt64
		eventTyp string
		status   string
		sent     sql.NullTime
	)
	if err := s.Scan(&d.ID, &ruleID, &chID, &eventTyp, &d.EventPayload,
		&d.RenderedPayload, &status, &d.ErrorMessage, &d.Attempts,
		&d.CreatedAt, &sent); err != nil {
		return d, err
	}
	d.EventType = EventType(eventTyp)
	d.Status = DeliveryStatus(status)
	if ruleID.Valid {
		v := ruleID.Int64
		d.RuleID = &v
	}
	if chID.Valid {
		v := chID.Int64
		d.ChannelID = &v
	}
	if sent.Valid {
		t := sent.Time
		d.SentAt = &t
	}
	return d, nil
}

func nullInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullTime(p *time.Time) any {
	if p == nil {
		return nil
	}
	return p.UTC()
}

// --- Push subscriptions ---

func (r *NotifRepo) ListPushSubs(ctx context.Context, userID int64) ([]PushSubscription, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT id, user_id, endpoint, p256dh_key, auth_key, user_agent, created_at
		FROM push_subscriptions WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.Endpoint, &s.P256dhKey, &s.AuthKey,
			&s.UserAgent, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListAllPushSubs returns every subscription (used by the browser_push
// sender for phase 5 fan-out to all admin devices).
func (r *NotifRepo) ListAllPushSubs(ctx context.Context) ([]PushSubscription, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT id, user_id, endpoint, p256dh_key, auth_key, user_agent, created_at
		FROM push_subscriptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.Endpoint, &s.P256dhKey, &s.AuthKey,
			&s.UserAgent, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *NotifRepo) UpsertPushSub(ctx context.Context, in *PushSubscription) (*PushSubscription, error) {
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO push_subscriptions (user_id, endpoint, p256dh_key, auth_key, user_agent)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, endpoint) DO UPDATE SET
		  p256dh_key = excluded.p256dh_key,
		  auth_key   = excluded.auth_key,
		  user_agent = excluded.user_agent`,
		in.UserID, in.Endpoint, in.P256dhKey, in.AuthKey, in.UserAgent)
	if err != nil {
		return nil, err
	}
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, user_id, endpoint, p256dh_key, auth_key, user_agent, created_at
		FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`,
		in.UserID, in.Endpoint)
	var s PushSubscription
	if err := row.Scan(&s.ID, &s.UserID, &s.Endpoint, &s.P256dhKey, &s.AuthKey,
		&s.UserAgent, &s.CreatedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *NotifRepo) DeletePushSub(ctx context.Context, userID int64, endpoint string) error {
	res, err := r.DB.ExecContext(ctx,
		`DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`, userID, endpoint)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSubscriptionNotFound
	}
	return nil
}

// DeletePushSubByEndpoint is called by the sender when the push service
// reports a 404/410 Gone for an endpoint -- the sub is stale.
func (r *NotifRepo) DeletePushSubByEndpoint(ctx context.Context, endpoint string) error {
	_, err := r.DB.ExecContext(ctx,
		`DELETE FROM push_subscriptions WHERE endpoint = ?`, endpoint)
	return err
}
