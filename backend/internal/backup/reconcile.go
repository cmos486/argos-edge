package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Reconcile brings the backups table and /data/backups/ back into
// sync. Called on every boot; idempotent when already in sync.
//
//   - files on disk without a row  -> insert (metadata.json parsed if
//     present, otherwise kind=orphan with a note)
//   - rows without a file on disk  -> delete (the tar.gz was removed
//     outside argos)
//   - files already tracked        -> skip; we trust the stored
//     sha256 rather than re-reading every archive on startup
func (m *Manager) Reconcile(ctx context.Context) error {
	if m.BackupDir == "" {
		return nil
	}
	if _, err := os.Stat(m.BackupDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat backup dir: %w", err)
	}

	// 1. disk view
	entries, err := os.ReadDir(m.BackupDir)
	if err != nil {
		return fmt.Errorf("read backup dir: %w", err)
	}
	onDisk := make(map[string]os.DirEntry, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		if strings.HasPrefix(name, ".") {
			// skip in-flight .partial / .upload- / .restore- artefacts
			continue
		}
		onDisk[name] = e
	}

	// 2. DB view
	rows, err := m.DB.QueryContext(ctx, `SELECT id, filename FROM backups`)
	if err != nil {
		return fmt.Errorf("list backups: %w", err)
	}
	inDB := make(map[string]int64)
	for rows.Next() {
		var id int64
		var fn string
		if err := rows.Scan(&id, &fn); err != nil {
			rows.Close()
			return err
		}
		inDB[fn] = id
	}
	rows.Close()

	added := 0
	pruned := 0
	unchanged := 0

	// 3. add orphan files (disk -> DB)
	for name, entry := range onDisk {
		if _, ok := inDB[name]; ok {
			unchanged++
			continue
		}
		if err := m.insertOrphan(ctx, name, entry); err != nil {
			slog.Warn("reconcile: insert orphan failed", "filename", name, "error", err)
			continue
		}
		added++
		slog.Info("reconcile: added orphan backup row", "filename", name)
	}

	// 4. prune rows whose file is missing (DB -> disk)
	for name, id := range inDB {
		if _, ok := onDisk[name]; ok {
			continue
		}
		if _, err := m.DB.ExecContext(ctx, `DELETE FROM backups WHERE id = ?`, id); err != nil {
			slog.Warn("reconcile: prune missing failed", "filename", name, "error", err)
			continue
		}
		pruned++
		slog.Info("pruned missing backup row", "filename", name)
	}

	slog.Info("reconcile complete",
		"added", added, "pruned", pruned, "unchanged", unchanged)
	return nil
}

// insertOrphan stats the file on disk, computes sha256, and tries to
// parse the embedded metadata.json. On any failure past sha256, falls
// back to kind="orphan" with mtime as created_at.
func (m *Manager) insertOrphan(ctx context.Context, name string, entry os.DirEntry) error {
	path := filepath.Join(m.BackupDir, name)
	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	size, sum, err := statAndSHA(path)
	if err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	kind := "orphan"
	note := "recovered during reconcile"
	createdAt := info.ModTime().UTC()
	if meta, err := readEmbeddedMetadata(path); err == nil {
		switch meta.Kind {
		case "manual", "scheduled":
			kind = meta.Kind
		}
		if !meta.CreatedAt.IsZero() {
			createdAt = meta.CreatedAt.UTC()
		}
		if meta.Note != "" && kind != "orphan" {
			note = meta.Note
		}
	}
	_, err = m.DB.ExecContext(ctx, `
		INSERT INTO backups (filename, size_bytes, sha256, kind, trigger_user_id, created_at, note)
		VALUES (?, ?, ?, ?, NULL, ?, ?)`,
		name, size, sum, kind, createdAt, note)
	return err
}

// readEmbeddedMetadata scans a tar.gz looking for metadata.json. Uses
// streaming reads so the archive does not need to be fully extracted
// to a temp dir.
func readEmbeddedMetadata(path string) (Metadata, error) {
	var zero Metadata
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return zero, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return zero, fmt.Errorf("metadata.json not found")
		}
		if err != nil {
			return zero, err
		}
		if filepath.Clean(hdr.Name) != MetadataFilename {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<10))
		if err != nil {
			return zero, err
		}
		var m Metadata
		if err := json.Unmarshal(b, &m); err != nil {
			return zero, err
		}
		if m.CreatedAt.IsZero() {
			// the file existed but timestamps were wonky; synthesise
			m.CreatedAt = time.Now().UTC()
		}
		return m, nil
	}
}
