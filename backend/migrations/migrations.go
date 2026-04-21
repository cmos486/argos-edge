// Package migrations embeds the SQL migration files so the argos binary
// is fully self-contained. The db package owns the runner that consumes
// FS plus any UpHooks / DownHooks registered here for migrations whose
// logic cannot be expressed in SQL alone (e.g. URL parsing in 005).
package migrations

import (
	"context"
	"database/sql"
	"embed"
)

//go:embed *.up.sql *.down.sql
var FS embed.FS

// HookFunc matches db.Hook; duplicated locally so this package stays
// importable from db without a cycle.
type HookFunc func(ctx context.Context, d *sql.DB) error

// UpHooks are Go-side upgrade hooks keyed by version. When a version
// has a hook, the corresponding .up.sql file (if any) is ignored.
var UpHooks = map[string]HookFunc{
	"005_hosts_to_target_groups": up005HostsToTargetGroups,
	"023_host_manual_certs":      up023HostManualCerts,
}

// DownHooks mirror UpHooks for rollbacks.
var DownHooks = map[string]HookFunc{
	"023_host_manual_certs": down023HostManualCerts,
}
