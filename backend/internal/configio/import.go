package configio

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// ImportMode enumerates the two behaviours the user selects.
type ImportMode string

const (
	ModeReplace ImportMode = "replace"
	ModeMerge   ImportMode = "merge"
)

// Parse reads YAML bytes into a ConfigBundle and does minimal
// validation. It does NOT talk to the DB.
func Parse(raw []byte) (*ConfigBundle, error) {
	var b ConfigBundle
	if err := yaml.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if b.Version == "" {
		return nil, errors.New("bundle missing 'version'")
	}
	if b.Version != BundleVersion {
		return nil, fmt.Errorf("unsupported bundle version %q (expected %q)", b.Version, BundleVersion)
	}
	return &b, nil
}

// Validate returns an ImportPlan describing what Apply would do. No
// write operations happen. For merge mode, Creates/Updates are
// computed by comparing natural keys; replace mode lists every bundle
// entity under Creates (and assumes all existing entities get wiped).
func Validate(ctx context.Context, d *sql.DB, repo *notifications.NotifRepo, b *ConfigBundle, mode ImportMode) (*ImportPlan, error) {
	plan := &ImportPlan{
		Mode:   string(mode),
		Counts: map[string]int{},
	}

	existingHosts, _ := db.ListHosts(ctx, d)
	existingHostDomains := make(map[string]bool, len(existingHosts))
	for _, h := range existingHosts {
		existingHostDomains[h.Domain] = true
	}
	existingTGs, _ := db.ListTargetGroups(ctx, d, false)
	existingTGNames := make(map[string]bool, len(existingTGs))
	for _, t := range existingTGs {
		existingTGNames[t.Name] = true
	}

	var existingChans []notifications.Channel
	if repo != nil {
		existingChans, _ = repo.ListChannels(ctx, false)
	}
	existingChanNames := make(map[string]bool, len(existingChans))
	for _, c := range existingChans {
		existingChanNames[c.Name] = true
	}

	// TG plan
	for _, tg := range b.TargetGroups {
		label := "tg:" + tg.Name
		if mode == ModeReplace || !existingTGNames[tg.Name] {
			plan.Creates = append(plan.Creates, label)
		} else {
			plan.Updates = append(plan.Updates, label)
		}
	}
	plan.Counts["target_groups"] = len(b.TargetGroups)

	// Host plan
	for _, h := range b.Hosts {
		label := "host:" + h.Domain
		if mode == ModeReplace || !existingHostDomains[h.Domain] {
			plan.Creates = append(plan.Creates, label)
		} else {
			plan.Updates = append(plan.Updates, label)
		}
		if h.TargetGroupName == "" {
			plan.Conflicts = append(plan.Conflicts, label+": host has no target_group")
		}
	}
	plan.Counts["hosts"] = len(b.Hosts)

	plan.Counts["rules"] = len(b.Rules)
	plan.Counts["host_security"] = len(b.HostSecurity)

	// Channel plan
	for _, c := range b.NotificationChannels {
		label := "channel:" + c.Name
		exists := existingChanNames[c.Name]
		if mode == ModeReplace || !exists {
			plan.Creates = append(plan.Creates, label)
			// Redacted secrets on a new channel => channel gets created
			// with empty secrets + enabled=false.
			for _, f := range channelSecretFields(c.Type) {
				if v, ok := c.Config[f]; ok {
					if s, _ := v.(string); s == RedactedPlaceholder {
						plan.Warnings = append(plan.Warnings,
							fmt.Sprintf("channel %q (%s): %s is redacted, will be empty after import; channel disabled",
								c.Name, c.Type, f))
					}
				}
			}
		} else {
			plan.Updates = append(plan.Updates, label)
		}
	}
	plan.Counts["notification_channels"] = len(b.NotificationChannels)
	plan.Counts["notification_rules"] = len(b.NotificationRules)
	plan.Counts["settings"] = len(b.Settings)

	return plan, nil
}

// Apply is the write path. Everything happens inside a single sql.Tx
// so a failure mid-way rolls the whole import back. The NotifRepo
// methods in the notifications package use the *sql.DB directly, so
// for the notification arms we build parallel SQL statements against
// the tx to keep the all-or-nothing guarantee.
//
// Warnings is populated for non-fatal issues: channels created with
// empty secrets, settings keys not in the whitelist, etc.
func Apply(ctx context.Context, d *sql.DB, b *ConfigBundle, mode ImportMode) (*ImportPlan, error) {
	if mode != ModeReplace && mode != ModeMerge {
		return nil, fmt.Errorf("invalid mode %q", mode)
	}
	plan := &ImportPlan{Mode: string(mode), Counts: map[string]int{}}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if mode == ModeReplace {
		// Order matters: children first. FK ON DELETE handles most of
		// the cascade already (rules FK host ON DELETE CASCADE,
		// exclusions likewise) but we're explicit for auditability.
		for _, q := range []string{
			`DELETE FROM notification_rules`,
			`DELETE FROM notification_channels`,
			`DELETE FROM waf_exclusions`,
			`DELETE FROM waf_custom_rules`,
			`DELETE FROM host_security`,
			`DELETE FROM rules`,
			`DELETE FROM hosts`,
			`DELETE FROM targets`,
			`DELETE FROM target_groups`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return nil, fmt.Errorf("wipe (%s): %w", q, err)
			}
		}
	}

	// Insert target groups first, record name -> id
	tgIDByName := make(map[string]int64, len(b.TargetGroups))
	for _, tg := range b.TargetGroups {
		id, err := upsertTargetGroup(ctx, tx, tg, mode)
		if err != nil {
			return nil, fmt.Errorf("tg %s: %w", tg.Name, err)
		}
		tgIDByName[tg.Name] = id
		plan.Counts["target_groups"]++
	}

	// Hosts (need TG ids resolved)
	hostIDByDomain := make(map[string]int64, len(b.Hosts))
	for _, h := range b.Hosts {
		tgID, ok := tgIDByName[h.TargetGroupName]
		if !ok {
			// Host YAML refers to a TG that is neither in the YAML
			// nor (on merge) already in DB -- hard failure.
			if mode == ModeMerge {
				var id int64
				if err := tx.QueryRowContext(ctx,
					`SELECT id FROM target_groups WHERE name = ?`, h.TargetGroupName).Scan(&id); err == nil {
					tgID = id
					ok = true
				}
			}
			if !ok {
				return nil, fmt.Errorf("host %s references unknown target_group %s", h.Domain, h.TargetGroupName)
			}
		}
		id, err := upsertHost(ctx, tx, h, tgID, mode)
		if err != nil {
			return nil, fmt.Errorf("host %s: %w", h.Domain, err)
		}
		hostIDByDomain[h.Domain] = id
		plan.Counts["hosts"]++
	}

	// Rules -- fill host_id from domain; merge mode: delete existing
	// rules for a host that appears in the bundle, then re-insert all
	// its rules from the bundle (simpler than per-rule priority merge).
	ruleHostsSeen := map[int64]bool{}
	for _, r := range b.Rules {
		hostID, ok := hostIDByDomain[r.HostDomain]
		if !ok {
			return nil, fmt.Errorf("rule references unknown host %s", r.HostDomain)
		}
		if mode == ModeMerge && !ruleHostsSeen[hostID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM rules WHERE host_id = ?`, hostID); err != nil {
				return nil, fmt.Errorf("rules wipe for host %d: %w", hostID, err)
			}
			ruleHostsSeen[hostID] = true
		}
		if err := insertRule(ctx, tx, hostID, r); err != nil {
			return nil, fmt.Errorf("rule host=%s prio=%d: %w", r.HostDomain, r.Priority, err)
		}
		plan.Counts["rules"]++
	}

	// Host security + exclusions + custom rules
	secHostsSeen := map[int64]bool{}
	for _, hs := range b.HostSecurity {
		hostID, ok := hostIDByDomain[hs.HostDomain]
		if !ok {
			return nil, fmt.Errorf("host_security references unknown host %s", hs.HostDomain)
		}
		if err := upsertHostSecurity(ctx, tx, hostID, hs); err != nil {
			return nil, fmt.Errorf("host_security %s: %w", hs.HostDomain, err)
		}
		if mode == ModeMerge && !secHostsSeen[hostID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM waf_exclusions WHERE host_id = ?`, hostID); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM waf_custom_rules WHERE host_id = ?`, hostID); err != nil {
				return nil, err
			}
			secHostsSeen[hostID] = true
		}
		for _, ex := range hs.Exclusions {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO waf_exclusions (host_id, crs_rule_id, path_pattern, reason, enabled)
				VALUES (?, ?, ?, ?, ?)`,
				hostID, ex.CRSRuleID, ex.PathPattern, ex.Reason, ex.Enabled); err != nil {
				return nil, fmt.Errorf("exclusion: %w", err)
			}
		}
		for _, cr := range hs.CustomRules {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO waf_custom_rules (host_id, name, secrule, enabled)
				VALUES (?, ?, ?, ?)`,
				hostID, cr.Name, cr.SecRule, cr.Enabled); err != nil {
				return nil, fmt.Errorf("custom rule: %w", err)
			}
		}
		plan.Counts["host_security"]++
	}

	// Notification channels. Look up previous ciphertext for merge mode
	// so UNCHANGED redacted secrets survive.
	prevChannelSecrets := map[string]map[string]string{} // name -> {secret_field -> ciphertext}
	rows, err := tx.QueryContext(ctx, `SELECT name, type, config FROM notification_channels`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, ctype, cfgStr string
		if err := rows.Scan(&name, &ctype, &cfgStr); err == nil {
			var cfg map[string]any
			_ = json.Unmarshal([]byte(cfgStr), &cfg)
			stored := map[string]string{}
			for _, f := range channelSecretFields(ctype) {
				if s, ok := cfg[f].(string); ok && crypto.IsEncrypted(s) {
					stored[f] = s
				}
			}
			prevChannelSecrets[name] = stored
		}
	}
	rows.Close()

	channelIDByName := map[string]int64{}
	for _, c := range b.NotificationChannels {
		id, warnings, err := upsertChannel(ctx, tx, c, mode, prevChannelSecrets[c.Name])
		if err != nil {
			return nil, fmt.Errorf("channel %s: %w", c.Name, err)
		}
		channelIDByName[c.Name] = id
		plan.Warnings = append(plan.Warnings, warnings...)
		plan.Counts["notification_channels"]++
	}

	// Notification rules
	for _, nr := range b.NotificationRules {
		chID, ok := channelIDByName[nr.ChannelName]
		if !ok {
			// lookup existing
			if err := tx.QueryRowContext(ctx,
				`SELECT id FROM notification_channels WHERE name = ?`, nr.ChannelName).Scan(&chID); err != nil {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("notif rule %q references unknown channel %q; skipped", nr.Name, nr.ChannelName))
				continue
			}
		}
		hostIDs := make([]int64, 0, len(nr.FilterHostDomains))
		for _, dom := range nr.FilterHostDomains {
			if id, ok := hostIDByDomain[dom]; ok {
				hostIDs = append(hostIDs, id)
			} else {
				// lookup
				var id int64
				if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE domain = ?`, dom).Scan(&id); err == nil {
					hostIDs = append(hostIDs, id)
				}
			}
		}
		hostJSON, _ := json.Marshal(hostIDs)
		sevJSON, _ := json.Marshal(nr.FilterSeverities)
		if mode == ModeMerge {
			if _, err := tx.ExecContext(ctx, `DELETE FROM notification_rules WHERE name = ?`, nr.Name); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO notification_rules
			  (name, channel_id, event_type, filter_host_ids, filter_severities,
			   enabled, throttle_window_seconds)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			nr.Name, chID, nr.EventType,
			nullIfEmpty(hostJSON), nullIfEmpty(sevJSON),
			nr.Enabled, nr.ThrottleWindowSeconds); err != nil {
			return nil, fmt.Errorf("notif rule %s: %w", nr.Name, err)
		}
		plan.Counts["notification_rules"]++
	}

	// Settings (whitelist only)
	for k, v := range b.Settings {
		if !exportableSettings[k] {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("setting %q is not importable (not in whitelist)", k))
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
			k, v); err != nil {
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
		plan.Counts["settings"]++
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return plan, nil
}

// --- helpers: upserts ---

func upsertTargetGroup(ctx context.Context, tx *sql.Tx, tg TargetGroupExport, mode ImportMode) (int64, error) {
	// Normalise defaults so the DB CHECK constraints are always
	// satisfied even when the YAML omits optional fields.
	if tg.HealthCheckMethod == "" {
		tg.HealthCheckMethod = "GET"
	}
	if tg.HealthCheckExpectStatus == "" {
		tg.HealthCheckExpectStatus = "200"
	}
	if tg.Algorithm == "" {
		tg.Algorithm = "round_robin"
	}
	if tg.Protocol == "" {
		tg.Protocol = "http"
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM target_groups WHERE name = ?`, tg.Name).Scan(&id)
	exists := err == nil
	if !exists && err != sql.ErrNoRows {
		return 0, err
	}
	if exists && mode == ModeMerge {
		// update in place
		if _, err := tx.ExecContext(ctx, `
			UPDATE target_groups SET protocol=?, verify_tls=?, algorithm=?,
			 health_check_enabled=?, health_check_path=?, health_check_method=?,
			 health_check_expect_status=?, health_check_interval_seconds=?,
			 health_check_timeout_seconds=?, health_check_fails_to_unhealthy=?,
			 health_check_passes_to_healthy=?, updated_at=CURRENT_TIMESTAMP
			 WHERE id = ?`,
			tg.Protocol, tg.VerifyTLS, tg.Algorithm,
			tg.HealthCheckEnabled, tg.HealthCheckPath, tg.HealthCheckMethod,
			tg.HealthCheckExpectStatus, tg.HealthCheckIntervalSeconds,
			tg.HealthCheckTimeoutSeconds, tg.HealthCheckFailsToUnhealthy,
			tg.HealthCheckPassesToHealthy, id); err != nil {
			return 0, err
		}
		// wipe + reinsert targets
		if _, err := tx.ExecContext(ctx, `DELETE FROM targets WHERE target_group_id = ?`, id); err != nil {
			return 0, err
		}
	} else {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO target_groups
			 (name, protocol, verify_tls, algorithm, health_check_enabled,
			  health_check_path, health_check_method, health_check_expect_status,
			  health_check_interval_seconds, health_check_timeout_seconds,
			  health_check_fails_to_unhealthy, health_check_passes_to_healthy)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tg.Name, tg.Protocol, tg.VerifyTLS, tg.Algorithm,
			tg.HealthCheckEnabled, tg.HealthCheckPath, tg.HealthCheckMethod,
			tg.HealthCheckExpectStatus, tg.HealthCheckIntervalSeconds,
			tg.HealthCheckTimeoutSeconds, tg.HealthCheckFailsToUnhealthy,
			tg.HealthCheckPassesToHealthy)
		if err != nil {
			return 0, err
		}
		id, _ = res.LastInsertId()
	}
	for _, t := range tg.Targets {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO targets (target_group_id, host, port, weight, enabled)
			VALUES (?, ?, ?, ?, ?)`,
			id, t.Host, t.Port, t.Weight, t.Enabled); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func upsertHost(ctx context.Context, tx *sql.Tx, h HostExport, tgID int64, mode ImportMode) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE domain = ?`, h.Domain).Scan(&id)
	exists := err == nil
	if !exists && err != sql.ErrNoRows {
		return 0, err
	}
	if exists && mode == ModeMerge {
		if _, err := tx.ExecContext(ctx, `
			UPDATE hosts SET target_group_id=?, tls_mode=?, tls_email=?, enabled=?,
			 updated_at=CURRENT_TIMESTAMP WHERE id = ?`,
			tgID, h.TLSMode, h.TLSEmail, h.Enabled, id); err != nil {
			return 0, err
		}
		return id, nil
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email, enabled)
		VALUES (?, ?, ?, ?, ?)`,
		h.Domain, tgID, h.TLSMode, h.TLSEmail, h.Enabled)
	if err != nil {
		return 0, err
	}
	id, _ = res.LastInsertId()
	return id, nil
}

func insertRule(ctx context.Context, tx *sql.Tx, hostID int64, r RuleExport) error {
	var action models.ActionEnv
	if err := json.Unmarshal(r.Action, &action); err != nil {
		return fmt.Errorf("decode action: %w", err)
	}
	matchers := make([]models.MatcherEnv, 0, len(r.Matchers))
	for _, m := range r.Matchers {
		var mm models.MatcherEnv
		if err := json.Unmarshal(m, &mm); err != nil {
			return fmt.Errorf("decode matcher: %w", err)
		}
		matchers = append(matchers, mm)
	}
	actCfg, _ := json.Marshal(action.Config)
	mBytes, _ := json.Marshal(matchers)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO rules
		 (host_id, priority, name, enabled, action_type, action_config, matchers_config)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hostID, r.Priority, r.Name, r.Enabled, string(action.Type), string(actCfg), string(mBytes))
	return err
}

func upsertHostSecurity(ctx context.Context, tx *sql.Tx, hostID int64, hs HostSecurityExport) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO host_security
		 (host_id, waf_enabled, waf_mode, waf_paranoia, waf_block_status, waf_block_body,
		  rate_limit_enabled, rate_limit_requests, rate_limit_window_seconds,
		  rate_limit_key, rate_limit_header_name, rate_limit_status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_id) DO UPDATE SET
		   waf_enabled = excluded.waf_enabled,
		   waf_mode = excluded.waf_mode,
		   waf_paranoia = excluded.waf_paranoia,
		   waf_block_status = excluded.waf_block_status,
		   waf_block_body = excluded.waf_block_body,
		   rate_limit_enabled = excluded.rate_limit_enabled,
		   rate_limit_requests = excluded.rate_limit_requests,
		   rate_limit_window_seconds = excluded.rate_limit_window_seconds,
		   rate_limit_key = excluded.rate_limit_key,
		   rate_limit_header_name = excluded.rate_limit_header_name,
		   rate_limit_status = excluded.rate_limit_status,
		   updated_at = CURRENT_TIMESTAMP`,
		hostID, hs.WAFEnabled, hs.WAFMode, hs.WAFParanoia, hs.WAFBlockStatus, hs.WAFBlockBody,
		hs.RateLimitEnabled, hs.RateLimitRequests, hs.RateLimitWindowSeconds,
		hs.RateLimitKey, hs.RateLimitHeaderName, hs.RateLimitStatus)
	return err
}

// upsertChannel handles the redacted-secret logic:
//   - merge mode + channel exists + secret is "__REDACTED__" -> keep prev ciphertext
//   - otherwise -> clear secret + flag channel disabled, add warning
func upsertChannel(ctx context.Context, tx *sql.Tx, c ChannelExport, mode ImportMode, prevSecrets map[string]string) (int64, []string, error) {
	var warnings []string
	cfg := make(map[string]any, len(c.Config))
	for k, v := range c.Config {
		cfg[k] = v
	}
	needsDisable := false
	for _, f := range channelSecretFields(c.Type) {
		if v, ok := cfg[f]; ok {
			if s, _ := v.(string); s == RedactedPlaceholder {
				if mode == ModeMerge && prevSecrets[f] != "" {
					cfg[f] = prevSecrets[f]
				} else {
					cfg[f] = ""
					needsDisable = true
					warnings = append(warnings,
						fmt.Sprintf("channel %q: %s reset to empty; disabled until reconfigured",
							c.Name, f))
				}
			}
		}
	}
	enabled := c.Enabled && !needsDisable
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return 0, warnings, err
	}

	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM notification_channels WHERE name = ?`, c.Name).Scan(&id)
	exists := err == nil
	if !exists && err != sql.ErrNoRows {
		return 0, warnings, err
	}
	if exists && mode == ModeMerge {
		if _, err := tx.ExecContext(ctx, `
			UPDATE notification_channels SET type=?, enabled=?, config=?, template=?,
			 rate_limit_per_minute=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			c.Type, enabled, string(cfgBytes), c.Template, c.RateLimitPerMinute, id); err != nil {
			return 0, warnings, err
		}
		return id, warnings, nil
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO notification_channels
		 (name, type, enabled, config, template, rate_limit_per_minute)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.Name, c.Type, enabled, string(cfgBytes), c.Template, c.RateLimitPerMinute)
	if err != nil {
		return 0, warnings, err
	}
	id, _ = res.LastInsertId()
	return id, warnings, nil
}

func nullIfEmpty(b []byte) any {
	// filter_host_ids and filter_severities are stored as TEXT; empty
	// slices become "null" JSON or "[]"; normalise to "" so WHERE
	// comparisons remain trivial.
	if string(b) == "null" || string(b) == "[]" {
		return ""
	}
	return string(b)
}
