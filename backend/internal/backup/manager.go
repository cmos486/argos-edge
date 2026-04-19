package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RestoreFlagFile lives inside argos_data (/data/.restore_pending) so
// it persists across the container restart triggered by /restore. The
// file contains the full path of the extracted tar.gz root directory;
// main.go reads it before opening the DB.
const RestoreFlagFile = "/data/.restore_pending"

// Manager owns the /data/backups/ directory and the backups table.
type Manager struct {
	DB          *sql.DB
	DBPath      string // absolute path to argos.db on disk
	CaddyDir    string // RO mount of caddy_data, empty if not mounted
	BackupDir   string // /data/backups inside the container
	ArgosVersion string
	Commit      string
}

// Backup is the persisted row + file metadata.
type Backup struct {
	ID            int64     `json:"id"`
	Filename      string    `json:"filename"`
	SizeBytes    int64     `json:"size_bytes"`
	SHA256        string    `json:"sha256"`
	Kind          string    `json:"kind"`
	TriggerUserID *int64    `json:"trigger_user_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	Note          string    `json:"note,omitempty"`
}

var (
	ErrBackupNotFound    = errors.New("backup not found")
	ErrInvalidArchive    = errors.New("backup archive is malformed")
	ErrSHA256Mismatch    = errors.New("sha256 mismatch: backup is corrupt or tampered")
	ErrRestoreInProgress = errors.New("restore already pending")
)

// Create produces a new backup tar.gz under BackupDir and records a
// row in the backups table. Steps (in order):
//   1. VACUUM INTO a temp file (consistent snapshot, no lock on live DB)
//   2. walk CaddyDir RO, piping every file into the tar
//   3. append metadata.json
//   4. close tar + gzip, rename temp -> final
//   5. compute sha256 of final file
//   6. insert row, return
// If any step fails, the temp dir is cleaned up and nothing is
// persisted.
func (m *Manager) Create(ctx context.Context, kind, note string, triggerUserID *int64) (*Backup, error) {
	if err := os.MkdirAll(m.BackupDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir backups: %w", err)
	}
	tmpDir, err := os.MkdirTemp(m.BackupDir, ".tmp-")
	if err != nil {
		return nil, fmt.Errorf("mkdir tmp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. VACUUM INTO -- produces a fully consistent copy with no WAL
	// files attached, ideal to ship in a tar.gz.
	snapshotPath := filepath.Join(tmpDir, "argos.db")
	if _, err := m.DB.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", snapshotPath)); err != nil {
		return nil, fmt.Errorf("vacuum into: %w", err)
	}
	dbStat, err := os.Stat(snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("stat snapshot: %w", err)
	}

	// 2. schema version = highest applied migration
	schemaVer := m.currentSchema(ctx)

	// 3. enumerate caddy files
	caddyFiles := 0
	if m.CaddyDir != "" {
		caddyFiles = countFiles(m.CaddyDir)
	}

	meta := Metadata{
		ArgosVersion:  m.ArgosVersion,
		Commit:        m.Commit,
		CreatedAt:     time.Now().UTC(),
		Kind:          kind,
		Note:          note,
		SchemaVersion: schemaVer,
		Contents: Contents{
			ArgosDB:    true,
			CaddyData:  caddyFiles > 0,
			CaddyFiles: caddyFiles,
			DBSize:     dbStat.Size(),
		},
	}

	filename := fmt.Sprintf("argos-backup-%s.tar.gz", meta.CreatedAt.Format("20060102-150405"))
	finalPath := filepath.Join(m.BackupDir, filename)
	// If a same-second backup already exists, skew the name rather than
	// overwrite. Defensive: clock jump.
	for i := 1; exists(finalPath); i++ {
		filename = fmt.Sprintf("argos-backup-%s-%d.tar.gz", meta.CreatedAt.Format("20060102-150405"), i)
		finalPath = filepath.Join(m.BackupDir, filename)
		if i > 100 {
			return nil, fmt.Errorf("too many same-name backups")
		}
	}
	tmpArchive := finalPath + ".partial"

	if err := m.writeArchive(tmpArchive, snapshotPath, meta); err != nil {
		os.Remove(tmpArchive)
		return nil, err
	}

	// 4. rename -> final (atomic on same filesystem)
	if err := os.Rename(tmpArchive, finalPath); err != nil {
		os.Remove(tmpArchive)
		return nil, fmt.Errorf("rename: %w", err)
	}

	// 5. stat + sha256
	size, sum, err := statAndSHA(finalPath)
	if err != nil {
		return nil, err
	}

	// 6. insert
	res, err := m.DB.ExecContext(ctx, `
		INSERT INTO backups (filename, size_bytes, sha256, kind, trigger_user_id, note)
		VALUES (?, ?, ?, ?, ?, ?)`,
		filename, size, sum, kind, nullInt64(triggerUserID), note)
	if err != nil {
		// inserting failed but the file exists; keep the file so the
		// operator can still restore from disk, and surface the error
		return nil, fmt.Errorf("insert backup row: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Backup{
		ID:            id,
		Filename:      filename,
		SizeBytes:    size,
		SHA256:        sum,
		Kind:          kind,
		TriggerUserID: triggerUserID,
		CreatedAt:     meta.CreatedAt,
		Note:          note,
	}, nil
}

func (m *Manager) writeArchive(path, snapshotPath string, meta Metadata) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// argos.db first so streaming reads can grab it without walking.
	if err := writeFileToTar(tw, snapshotPath, DBFilename); err != nil {
		return fmt.Errorf("tar argos.db: %w", err)
	}
	// metadata.json
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := writeBytesToTar(tw, MetadataFilename, metaBytes); err != nil {
		return fmt.Errorf("tar metadata: %w", err)
	}
	// caddy tree (read-only, may be empty)
	if m.CaddyDir != "" {
		if err := m.walkCaddy(tw); err != nil {
			return fmt.Errorf("tar caddy: %w", err)
		}
	}
	return nil
}

func (m *Manager) walkCaddy(tw *tar.Writer) error {
	return filepath.Walk(m.CaddyDir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			// caddy_data is mounted read-only and is owned by whoever
			// runs the caddy container (often root); file-level perms
			// may deny argos's "nobody" uid. Skip unreadable entries
			// silently -- backups are best-effort for caddy state.
			return nil
		}
		if info.IsDir() {
			return nil
		}
		// Probe readability BEFORE writing the tar header: if we write
		// the header first and then fail to open, the tar is
		// half-written and corrupt. Open() + immediate close is cheap.
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil // unreadable, skip
		}
		f.Close()
		rel, err := filepath.Rel(m.CaddyDir, path)
		if err != nil {
			return err
		}
		if err := writeFileToTar(tw, path, CaddyDir+rel); err != nil {
			// Second-line defence: if the file vanished between probe
			// and copy, skip rather than abort.
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil
			}
			return err
		}
		return nil
	})
}

// List returns backups newest-first.
func (m *Manager) List(ctx context.Context, limit int) ([]Backup, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := m.DB.QueryContext(ctx, `
		SELECT id, filename, size_bytes, sha256, kind, trigger_user_id, created_at, note
		FROM backups
		ORDER BY created_at DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Get returns one backup by id.
func (m *Manager) Get(ctx context.Context, id int64) (*Backup, error) {
	row := m.DB.QueryRowContext(ctx, `
		SELECT id, filename, size_bytes, sha256, kind, trigger_user_id, created_at, note
		FROM backups WHERE id = ?`, id)
	b, err := scanBackup(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrBackupNotFound
		}
		return nil, err
	}
	return &b, nil
}

// Delete removes the file on disk plus the row. Non-fatal if the file
// is already gone (row still dropped).
func (m *Manager) Delete(ctx context.Context, id int64) error {
	b, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	path := filepath.Join(m.BackupDir, b.Filename)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove file: %w", err)
	}
	if _, err := m.DB.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete row: %w", err)
	}
	return nil
}

// Purge enforces backup.retention_days: any backup older than the
// cutoff gets deleted. retentionDays <= 0 prunes everything except
// the single newest backup (which is always preserved so a buggy
// schedule cannot leave the operator with zero recovery options).
func (m *Manager) Purge(ctx context.Context, retentionDays int) (int, error) {
	list, err := m.List(ctx, 1000)
	if err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, nil
	}
	// keep the newest no matter what
	newestID := list[0].ID
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	deleted := 0
	for _, b := range list {
		if b.ID == newestID {
			continue
		}
		if retentionDays <= 0 || b.CreatedAt.Before(cutoff) {
			if err := m.Delete(ctx, b.ID); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

// --- Prepare + Apply (restore) ---

// RestorePlan describes the outcome of Prepare: what is in the tar.gz
// and whether it is safe to apply on top of the current state.
type RestorePlan struct {
	BackupID       int64     `json:"backup_id,omitempty"`
	Filename       string    `json:"filename"`
	SizeBytes      int64     `json:"size_bytes"`
	SHA256         string    `json:"sha256"`
	Metadata       Metadata  `json:"metadata"`
	CurrentSchema  string    `json:"current_schema"`
	Warnings       []string  `json:"warnings,omitempty"`
	ExtractedPath  string    `json:"-"` // absolute tmp dir with expanded contents
}

// Prepare extracts the archive into a tmp directory next to
// BackupDir, verifies the sha256 if the caller supplied one, parses
// metadata.json, and returns a plan. The caller then calls Apply.
//
// If backupID is non-zero, the manager cross-checks the stored sha256
// and refuses to continue on mismatch.
func (m *Manager) Prepare(ctx context.Context, path string, backupID int64) (*RestorePlan, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	size, sum, err := statAndSHA(path)
	if err != nil {
		return nil, err
	}
	if backupID > 0 {
		b, err := m.Get(ctx, backupID)
		if err != nil {
			return nil, err
		}
		if b.SHA256 != sum {
			return nil, ErrSHA256Mismatch
		}
	}

	extractRoot := filepath.Join(m.BackupDir, ".restore-"+time.Now().UTC().Format("20060102150405"))
	if err := os.MkdirAll(extractRoot, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir restore: %w", err)
	}
	if err := extractArchive(path, extractRoot); err != nil {
		os.RemoveAll(extractRoot)
		return nil, err
	}

	metaPath := filepath.Join(extractRoot, MetadataFilename)
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		os.RemoveAll(extractRoot)
		return nil, fmt.Errorf("%w: missing metadata.json", ErrInvalidArchive)
	}
	var meta Metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		os.RemoveAll(extractRoot)
		return nil, fmt.Errorf("%w: metadata: %v", ErrInvalidArchive, err)
	}

	dbPath := filepath.Join(extractRoot, DBFilename)
	if _, err := os.Stat(dbPath); err != nil {
		os.RemoveAll(extractRoot)
		return nil, fmt.Errorf("%w: missing argos.db", ErrInvalidArchive)
	}

	current := m.currentSchema(ctx)
	plan := &RestorePlan{
		Filename:      filepath.Base(path),
		SizeBytes:    size,
		SHA256:        sum,
		Metadata:      meta,
		CurrentSchema: current,
		ExtractedPath: extractRoot,
	}
	_ = info // retained for future size checks
	if meta.SchemaVersion != "" && current != "" && meta.SchemaVersion > current {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("backup was taken on a newer schema (%s); downgrade blocked", meta.SchemaVersion))
		// don't auto-fail here; surface warning in UI. Apply enforces it.
	}
	return plan, nil
}

// Apply writes the restore flag file and returns. The caller should
// os.Exit(0) shortly after so Docker's restart policy picks up; the
// reborn process honours the flag in main.go and swaps argos.db in
// before opening the connection pool.
func (m *Manager) Apply(plan *RestorePlan) error {
	if plan == nil {
		return errors.New("nil plan")
	}
	if plan.Metadata.SchemaVersion != "" && plan.CurrentSchema != "" &&
		plan.Metadata.SchemaVersion > plan.CurrentSchema {
		return fmt.Errorf("cannot restore: backup schema %s > current %s",
			plan.Metadata.SchemaVersion, plan.CurrentSchema)
	}
	if _, err := os.Stat(RestoreFlagFile); err == nil {
		return ErrRestoreInProgress
	}
	if err := os.WriteFile(RestoreFlagFile, []byte(plan.ExtractedPath+"\n"), 0o600); err != nil {
		return fmt.Errorf("write restore flag: %w", err)
	}
	return nil
}

// ApplyPending is called from main.go BEFORE opening the SQLite pool.
// If the flag file exists, move argos.db from the extracted dir over
// the live DB path, delete the flag, and return the backup filename
// so main can emit a config_restored event once notifications start.
//
// Nothing is restored besides argos.db per the user's scope decision:
// Caddy data is intentionally left as-is so Caddy re-issues certs.
func ApplyPending(dbPath string) (appliedFrom string, err error) {
	raw, rerr := os.ReadFile(RestoreFlagFile)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return "", nil
		}
		return "", rerr
	}
	extractRoot := strings.TrimSpace(string(raw))
	srcDB := filepath.Join(extractRoot, DBFilename)
	if _, err := os.Stat(srcDB); err != nil {
		// flag present but payload missing; clean up so we don't loop
		os.Remove(RestoreFlagFile)
		return "", fmt.Errorf("restore payload missing argos.db at %s", srcDB)
	}

	// Read metadata for the "appliedFrom" label.
	applied := "unknown"
	if metaBytes, err := os.ReadFile(filepath.Join(extractRoot, MetadataFilename)); err == nil {
		var meta Metadata
		if json.Unmarshal(metaBytes, &meta) == nil {
			applied = fmt.Sprintf("backup from %s (kind=%s)", meta.CreatedAt.Format(time.RFC3339), meta.Kind)
		}
	}

	// Remove any WAL / SHM that outlived the old DB so the new one
	// opens cleanly.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(dbPath + suffix)
	}
	if err := copyFile(srcDB, dbPath); err != nil {
		return "", fmt.Errorf("replace db: %w", err)
	}
	// Clean up the extracted tree and flag
	os.RemoveAll(extractRoot)
	os.Remove(RestoreFlagFile)
	return applied, nil
}

// currentSchema returns the highest applied migration version so the
// backup metadata lets future restores refuse downgrades.
func (m *Manager) currentSchema(ctx context.Context) string {
	row := m.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), '') FROM schema_migrations`)
	var v string
	_ = row.Scan(&v)
	return v
}

// --- helpers ---

func scanBackup(s interface{ Scan(...any) error }) (Backup, error) {
	var (
		b        Backup
		userID   sql.NullInt64
		note     sql.NullString
	)
	if err := s.Scan(&b.ID, &b.Filename, &b.SizeBytes, &b.SHA256, &b.Kind,
		&userID, &b.CreatedAt, &note); err != nil {
		return b, err
	}
	if userID.Valid {
		v := userID.Int64
		b.TriggerUserID = &v
	}
	if note.Valid {
		b.Note = note.String
	}
	return b, nil
}

func nullInt64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func writeFileToTar(tw *tar.Writer, srcPath, dstPath string) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    dstPath,
		Size:    info.Size(),
		Mode:    0o600,
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func writeBytesToTar(tw *tar.Writer, dstPath string, content []byte) error {
	hdr := &tar.Header{
		Name:    dstPath,
		Size:    int64(len(content)),
		Mode:    0o600,
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}

func statAndSHA(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func countFiles(root string) int {
	n := 0
	filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// extractArchive unpacks a tar.gz into dst. Rejects absolute paths and
// "../" traversal inside the tar (defence in depth -- the archives we
// produce never contain either).
func extractArchive(archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip: %w", ErrInvalidArchive)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", ErrInvalidArchive)
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") {
			return fmt.Errorf("%w: unsafe path %s", ErrInvalidArchive, hdr.Name)
		}
		out := filepath.Join(dst, clean)
		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		w, err := os.Create(out)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return err
		}
		w.Close()
	}
	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	d, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// sortedFilenames is a tiny helper used by the CLI subcommand list
// view. Exposed so the test suite can verify determinism.
func sortedFilenames(list []Backup) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, b.Filename)
	}
	sort.Strings(out)
	return out
}

var _ = sortedFilenames
