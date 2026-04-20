// Package backup owns local tar.gz backup + restore of argos state.
//
// A backup bundles: the panel's SQLite DB (snapshot via VACUUM INTO
// so live writes do not corrupt the copy), a read-only copy of
// Caddy's TLS storage (certs + ACME account), and a metadata.json
// describing version + schema state. Restore only replays argos.db;
// Caddy re-issues certs via DNS-01 after the panel restarts.
package backup

import "time"

// MetadataFilename is the name inside every tar.gz.
const MetadataFilename = "metadata.json"

// DBFilename is the path within the tar.gz for the SQLite snapshot.
const DBFilename = "argos.db"

// CaddyDir is the prefix for the (read-only, informational) caddy
// storage tree inside the tar.gz. "caddy/" is used so operators can
// clearly distinguish it if they untar manually.
const CaddyDir = "caddy/"

// Metadata is the top-level JSON document shipped inside every backup.
// Kept narrow: anything that drifts as argos evolves (DB schema,
// config shape, argos version) belongs here so a future restore can
// refuse downgrades or warn on shape skew.
type Metadata struct {
	ArgosVersion  string    `json:"argos_version"`
	Commit        string    `json:"commit,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	Kind          string    `json:"kind"` // manual | scheduled
	Note          string    `json:"note,omitempty"`
	SchemaVersion string    `json:"schema_version"`
	Contents      Contents  `json:"contents"`
}

// Contents documents what is present in the tar.gz so the UI can
// summarise "argos.db + 4 hosts of caddy certs + metadata" without
// untarring.
type Contents struct {
	ArgosDB    bool  `json:"argos_db"`
	CaddyData  bool  `json:"caddy_data"`
	CaddyFiles int   `json:"caddy_files"`
	DBSize     int64 `json:"db_size_bytes"`
}
