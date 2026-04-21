package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrManualCertNotFound signals no row exists for the given host.
var ErrManualCertNotFound = errors.New("manual cert not found")

// ManualCertRow is the DB projection of host_manual_certs.
type ManualCertRow struct {
	ID                int64
	HostID            int64
	CertPEM           string
	KeyPEMEncrypted   []byte
	ChainPEM          string
	NotAfter          time.Time
	NotBefore         time.Time
	SANs              string // JSON array
	FingerprintSHA256 string
	UploadedAt        time.Time
	UploadedBy        int64
}

// UpsertManualCertInput carries the fields the API writes. The DB
// layer encrypts via the caller (crypto.Cipher lives in api); we just
// accept the pre-encrypted blob here.
type UpsertManualCertInput struct {
	HostID            int64
	CertPEM           string
	KeyPEMEncrypted   []byte
	ChainPEM          string
	NotAfter          time.Time
	NotBefore         time.Time
	SANs              string
	FingerprintSHA256 string
	UploadedBy        int64
}

// UpsertManualCert inserts or replaces the manual cert for a host.
// Per the UNIQUE(host_id) constraint, a host has at most one manual
// cert at a time. The UploadedAt column is refreshed on every call.
func UpsertManualCert(ctx context.Context, d *sql.DB, in UpsertManualCertInput) (ManualCertRow, error) {
	if _, err := d.ExecContext(ctx, `
		INSERT INTO host_manual_certs
			(host_id, cert_pem, key_pem_encrypted, chain_pem,
			 not_after, not_before, sans, fingerprint_sha256, uploaded_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET
			cert_pem           = excluded.cert_pem,
			key_pem_encrypted  = excluded.key_pem_encrypted,
			chain_pem          = excluded.chain_pem,
			not_after          = excluded.not_after,
			not_before         = excluded.not_before,
			sans               = excluded.sans,
			fingerprint_sha256 = excluded.fingerprint_sha256,
			uploaded_at        = CURRENT_TIMESTAMP,
			uploaded_by        = excluded.uploaded_by`,
		in.HostID, in.CertPEM, in.KeyPEMEncrypted, in.ChainPEM,
		in.NotAfter, in.NotBefore, in.SANs, in.FingerprintSHA256, in.UploadedBy,
	); err != nil {
		return ManualCertRow{}, fmt.Errorf("upsert manual cert: %w", err)
	}
	return GetManualCertByHostID(ctx, d, in.HostID)
}

// GetManualCertByHostID returns the single row for host. Returns
// ErrManualCertNotFound when no row exists.
func GetManualCertByHostID(ctx context.Context, d *sql.DB, hostID int64) (ManualCertRow, error) {
	row := d.QueryRowContext(ctx, `
		SELECT id, host_id, cert_pem, key_pem_encrypted, chain_pem,
		       not_after, not_before, sans, fingerprint_sha256,
		       uploaded_at, uploaded_by
		  FROM host_manual_certs WHERE host_id = ?`, hostID)
	var r ManualCertRow
	err := row.Scan(&r.ID, &r.HostID, &r.CertPEM, &r.KeyPEMEncrypted, &r.ChainPEM,
		&r.NotAfter, &r.NotBefore, &r.SANs, &r.FingerprintSHA256,
		&r.UploadedAt, &r.UploadedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return ManualCertRow{}, ErrManualCertNotFound
	}
	if err != nil {
		return ManualCertRow{}, fmt.Errorf("scan manual cert: %w", err)
	}
	return r, nil
}

// ListManualCerts returns every manual cert joined with its host
// domain so the /api/manual-certs endpoint can render the list
// without a second query per row.
type ManualCertListItem struct {
	ManualCertRow
	Domain string
}

func ListManualCerts(ctx context.Context, d *sql.DB) ([]ManualCertListItem, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT m.id, m.host_id, m.cert_pem, m.key_pem_encrypted, m.chain_pem,
		       m.not_after, m.not_before, m.sans, m.fingerprint_sha256,
		       m.uploaded_at, m.uploaded_by, h.domain
		  FROM host_manual_certs m
		  JOIN hosts h ON h.id = m.host_id
		 ORDER BY h.domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("list manual certs: %w", err)
	}
	defer rows.Close()
	var out []ManualCertListItem
	for rows.Next() {
		var r ManualCertListItem
		if err := rows.Scan(&r.ID, &r.HostID, &r.CertPEM, &r.KeyPEMEncrypted, &r.ChainPEM,
			&r.NotAfter, &r.NotBefore, &r.SANs, &r.FingerprintSHA256,
			&r.UploadedAt, &r.UploadedBy, &r.Domain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteManualCert removes the row for host. Missing row returns
// ErrManualCertNotFound so the handler can 404 cleanly.
func DeleteManualCert(ctx context.Context, d *sql.DB, hostID int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM host_manual_certs WHERE host_id = ?`, hostID)
	if err != nil {
		return fmt.Errorf("delete manual cert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrManualCertNotFound
	}
	return nil
}
