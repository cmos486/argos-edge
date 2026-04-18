// Package migrations embeds the SQL migration files so the argos binary is
// fully self-contained. The db package owns the runner that consumes FS.
package migrations

import "embed"

//go:embed *.up.sql *.down.sql
var FS embed.FS
