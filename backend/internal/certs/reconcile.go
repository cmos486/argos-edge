package certs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// ReconcileManualCerts ensures every host_manual_certs row has its
// plaintext .crt + .key files materialised on disk. It is the DR
// path for a fresh-infra restore: the tar.gz backup captures
// argos.db (including host_manual_certs with the encrypted key) but
// NOT the plaintext files on the caddy_manual_certs volume. When
// the panel boots onto a wiped volume, Caddy's load_files entries
// would point at non-existent paths; this reconcile materialises
// them from the encrypted DB so Caddy's first /load succeeds.
//
// Idempotent: rows whose .crt AND .key are already present on disk
// are skipped cheaply (two os.Stat calls, no decrypt). Rows whose
// encrypted key cannot be decrypted (usually a changed
// ARGOS_MASTER_KEY) surface as per-row errors without aborting the
// rest.
//
// Returns the count of rows materialised on this call plus a slice
// of per-row errors. The caller logs both; no single error is
// returned because one bad row should not hide a successful
// reconcile of its siblings.
func ReconcileManualCerts(ctx context.Context, d *sql.DB, store *Store, cipher *crypto.Cipher) (int, []error) {
	if d == nil || store == nil || cipher == nil {
		return 0, []error{errors.New("manual cert reconcile: nil dependency")}
	}
	rows, err := db.ListManualCerts(ctx, d)
	if err != nil {
		return 0, []error{fmt.Errorf("manual cert reconcile: list: %w", err)}
	}

	var errs []error
	reconciled := 0
	for _, row := range rows {
		certPath := store.CertPath(row.HostID)
		keyPath := store.KeyPath(row.HostID)

		// Both files present = nothing to do. We don't verify content
		// matches the DB row: the upload path is the only writer under
		// normal operation, and blindly overwriting on every boot
		// would be a foot-gun if the operator ever hot-edited the
		// files for debugging.
		if fileExists(certPath) && fileExists(keyPath) {
			continue
		}

		keyPEM, err := cipher.Decrypt(string(row.KeyPEMEncrypted))
		if err != nil {
			errs = append(errs, fmt.Errorf("host %d (%s): decrypt key: %w", row.HostID, row.Domain, err))
			continue
		}

		// Feed the existing Store.Write path so atomicity (tmp file +
		// rename) + file-permission policy stay consistent with the
		// upload write path.
		v := &Validated{
			CertPEM:  row.CertPEM,
			ChainPEM: row.ChainPEM,
			KeyPEM:   keyPEM,
		}
		if err := store.Write(row.HostID, v); err != nil {
			errs = append(errs, fmt.Errorf("host %d (%s): write files: %w", row.HostID, row.Domain, err))
			continue
		}
		slog.Info("manual cert reconcile: materialised files",
			"host_id", row.HostID,
			"domain", row.Domain)
		reconciled++
	}
	return reconciled, errs
}

// fileExists returns true for a regular file that os.Stat can reach.
// Directory / broken-symlink / permission-denied all read as "not
// there" so the reconciler retries writing -- the follow-up write
// will produce a clearer error than a bare os.Stat failure.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
