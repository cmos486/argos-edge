package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	_ "modernc.org/sqlite"
)

// newMigrationTestDB creates an in-memory SQLite with the minimal
// notification_channels schema the migration touches. Single-connection
// cap because :memory: is per-conn (each new connection sees its own
// fresh DB), which the rest of the project's notification tests handle
// the same way.
func newMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE notification_channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			config TEXT NOT NULL DEFAULT '{}',
			template TEXT,
			rate_limit_per_minute INTEGER NOT NULL DEFAULT 10,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func insertChannel(t *testing.T, db *sql.DB, name, typ, template string, config map[string]any) int64 {
	t.Helper()
	cfg := "{}"
	if config != nil {
		b, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("marshal cfg: %v", err)
		}
		cfg = string(b)
	}
	res, err := db.Exec(
		`INSERT INTO notification_channels (name, type, template, config) VALUES (?, ?, ?, ?)`,
		name, typ, template, cfg)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func channelState(t *testing.T, db *sql.DB, id int64) (template string, config map[string]any) {
	t.Helper()
	var tmpl sql.NullString
	var cfgStr string
	if err := db.QueryRow(
		`SELECT template, config FROM notification_channels WHERE id = ?`, id,
	).Scan(&tmpl, &cfgStr); err != nil {
		t.Fatalf("select id=%d: %v", id, err)
	}
	if cfgStr != "" {
		_ = json.Unmarshal([]byte(cfgStr), &config)
	}
	return tmpl.String, config
}

// quietLogger discards INFO output so test runs stay clean.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMigrateClearsExactMatchTemplate covers the v1.3.34.2 happy path:
// a Telegram channel persisted with the byte-exact pre-v1.3.34.1
// MarkdownV2 default in its template column gets cleared, so Render's
// empty-fallback kicks in.
func TestMigrateClearsExactMatchTemplate(t *testing.T) {
	db := newMigrationTestDB(t)
	id := insertChannel(t, db, "ops",
		string(TypeTelegram),
		LegacyTelegramDefaultTemplate,
		map[string]any{"bot_token": "x", "chat_id": "1"},
	)
	n, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger())
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 row touched, got %d", n)
	}
	tmpl, _ := channelState(t, db, id)
	if tmpl != "" {
		t.Errorf("template not cleared: %q", tmpl)
	}
}

// TestMigrateClearsParseModeMarkdownV2 covers the second surface: a
// channel with parse_mode pinned in config.MarkdownV2 gets the key
// removed from the JSON blob.
func TestMigrateClearsParseModeMarkdownV2(t *testing.T) {
	db := newMigrationTestDB(t)
	id := insertChannel(t, db, "ops",
		string(TypeTelegram),
		"", // template empty (already on the new fallback path)
		map[string]any{
			"bot_token":  "x",
			"chat_id":    "1",
			"parse_mode": "MarkdownV2",
		},
	)
	if _, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, cfg := channelState(t, db, id)
	if _, present := cfg["parse_mode"]; present {
		t.Errorf("parse_mode key should have been removed; cfg=%v", cfg)
	}
	if cfg["bot_token"] != "x" || cfg["chat_id"] != "1" {
		t.Errorf("non-target keys mutated; cfg=%v", cfg)
	}
}

// TestMigrateLeavesCustomisedTemplateAlone is the safety guarantee: a
// one-byte deviation from the legacy literal means the operator
// intentionally customised the template, and the migration MUST NOT
// touch it.
func TestMigrateLeavesCustomisedTemplateAlone(t *testing.T) {
	db := newMigrationTestDB(t)
	customised := LegacyTelegramDefaultTemplate + " " // trailing space
	id := insertChannel(t, db, "ops",
		string(TypeTelegram),
		customised,
		map[string]any{"bot_token": "x", "chat_id": "1"},
	)
	if _, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	tmpl, _ := channelState(t, db, id)
	if tmpl != customised {
		t.Errorf("customised template was mutated: %q", tmpl)
	}
}

// TestMigrateLeavesParseModeHTMLAlone asserts that a channel which
// already has parse_mode=HTML pinned (or any other non-MarkdownV2
// value) is not re-mutated.
func TestMigrateLeavesParseModeHTMLAlone(t *testing.T) {
	db := newMigrationTestDB(t)
	id := insertChannel(t, db, "ops",
		string(TypeTelegram),
		"",
		map[string]any{
			"bot_token":  "x",
			"chat_id":    "1",
			"parse_mode": "HTML",
		},
	)
	if _, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, cfg := channelState(t, db, id)
	if cfg["parse_mode"] != "HTML" {
		t.Errorf("HTML parse_mode should be untouched, got %v", cfg["parse_mode"])
	}
}

// TestMigrateIsIdempotent runs the migration twice; the second run must
// touch zero rows even though the first touched several.
func TestMigrateIsIdempotent(t *testing.T) {
	db := newMigrationTestDB(t)
	insertChannel(t, db, "a", string(TypeTelegram), LegacyTelegramDefaultTemplate, nil)
	insertChannel(t, db, "b", string(TypeTelegram), "",
		map[string]any{"parse_mode": "MarkdownV2"})

	first, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first == 0 {
		t.Fatal("expected first run to touch rows")
	}
	second, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second != 0 {
		t.Errorf("expected second run to be a no-op, got %d", second)
	}
}

// TestMigrateIgnoresNonTelegramChannels asserts the WHERE type='telegram'
// scope: webhook / email / browser_push channels with the same literal
// in template (impossible in practice, but defended against) are not
// touched.
func TestMigrateIgnoresNonTelegramChannels(t *testing.T) {
	db := newMigrationTestDB(t)
	wid := insertChannel(t, db, "wh", string(TypeWebhook), LegacyTelegramDefaultTemplate, nil)
	if _, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	tmpl, _ := channelState(t, db, wid)
	if tmpl != LegacyTelegramDefaultTemplate {
		t.Errorf("non-telegram channel mutated: %q", tmpl)
	}
}

// TestMigrateBothSurfacesOnSameChannel: a single channel has BOTH the
// legacy template literal AND parse_mode=MarkdownV2 (the worst-case
// pre-v1.3.34.1 row). Migration must clean both, and the count
// reflects that.
func TestMigrateBothSurfacesOnSameChannel(t *testing.T) {
	db := newMigrationTestDB(t)
	id := insertChannel(t, db, "ops",
		string(TypeTelegram),
		LegacyTelegramDefaultTemplate,
		map[string]any{"parse_mode": "MarkdownV2", "chat_id": "1"},
	)
	n, err := MigrateLegacyTelegramChannels(context.Background(), db, quietLogger())
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 surfaces touched, got %d", n)
	}
	tmpl, cfg := channelState(t, db, id)
	if tmpl != "" {
		t.Errorf("template not cleared: %q", tmpl)
	}
	if _, present := cfg["parse_mode"]; present {
		t.Errorf("parse_mode not cleared")
	}
}
