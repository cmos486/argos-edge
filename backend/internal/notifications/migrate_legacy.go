package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
)

// MigrateLegacyTelegramChannels clears persisted v1.3.21..v1.3.34
// MarkdownV2 defaults from existing Telegram channels so they fall
// through to the v1.3.34.1 HTML default at render time.
//
// Two surfaces get touched, both idempotent and exact-match:
//
//  1. notification_channels.template — when its content is byte-equal
//     to LegacyTelegramDefaultTemplate, set it to ''. A one-byte
//     deviation (operator customisation) leaves the row untouched.
//  2. config.parse_mode — when set to 'MarkdownV2' in the JSON, the
//     key is removed from the encrypted config blob. Any other value
//     ('HTML', a custom mode, or absent) is left untouched.
//
// Returns the number of rows touched (template-clear + config-update
// counted independently; a single channel can produce 2). Logs an INFO
// line with the counts so the operator can see migration ran on boot.
//
// MUST run after schema migrations and before HTTP serving begins so
// the first SendTest hit post-deploy uses the cleaned state.
func MigrateLegacyTelegramChannels(ctx context.Context, db *sql.DB, logger *slog.Logger) (int, error) {
	if logger == nil {
		logger = slog.Default()
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, template, config FROM notification_channels WHERE type = 'telegram'`)
	if err != nil {
		return 0, fmt.Errorf("query telegram channels: %w", err)
	}
	type row struct {
		id       int64
		template sql.NullString
		config   string
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.template, &r.config); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		found = append(found, r)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var templateCleared, parseModeCleared int
	for _, r := range found {
		// 1. Template column
		if r.template.Valid && r.template.String == LegacyTelegramDefaultTemplate {
			if _, err := db.ExecContext(ctx,
				`UPDATE notification_channels SET template = '',
				 updated_at = CURRENT_TIMESTAMP WHERE id = ?`, r.id); err != nil {
				return templateCleared + parseModeCleared,
					fmt.Errorf("clear template id=%d: %w", r.id, err)
			}
			templateCleared++
			logger.Info("notifications: cleared legacy MarkdownV2 default template",
				"channel_id", r.id)
		}

		// 2. parse_mode key inside config JSON
		if r.config == "" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(r.config), &cfg); err != nil {
			// don't block boot on a malformed row; log and skip
			logger.Warn("notifications: skip channel with malformed config",
				"channel_id", r.id, "err", err)
			continue
		}
		pm, ok := cfg["parse_mode"].(string)
		if !ok || pm != "MarkdownV2" {
			continue
		}
		delete(cfg, "parse_mode")
		newCfg, err := json.Marshal(cfg)
		if err != nil {
			return templateCleared + parseModeCleared,
				fmt.Errorf("marshal cleaned config id=%d: %w", r.id, err)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE notification_channels SET config = ?,
			 updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			string(newCfg), r.id); err != nil {
			return templateCleared + parseModeCleared,
				fmt.Errorf("clear parse_mode id=%d: %w", r.id, err)
		}
		parseModeCleared++
		logger.Info("notifications: cleared pinned MarkdownV2 parse_mode",
			"channel_id", r.id)
	}

	total := templateCleared + parseModeCleared
	if total > 0 || len(found) > 0 {
		logger.Info("notifications: legacy Telegram migration complete",
			"channels_scanned", len(found),
			"templates_cleared", templateCleared,
			"parse_modes_cleared", parseModeCleared)
	}
	return total, nil
}
