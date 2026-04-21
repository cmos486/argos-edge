package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/dnsproviders"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// ErrDNSProviderNotFound is returned when a lookup targets a name the
// catalogue seeded but which (somehow) lacks a row. Seeded rows are
// inserted at migration time so this mostly surfaces programmer error.
var ErrDNSProviderNotFound = errors.New("dns provider not found")

// ListDNSProviders returns every seeded provider row in stable name
// order. Includes enabled=false rows so the Settings page can show
// every supported provider even when none are configured.
func ListDNSProviders(ctx context.Context, d *sql.DB) ([]models.DNSProviderRow, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, name, enabled, credentials_encrypted, updated_at
		   FROM dns_providers
		  ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("query dns_providers: %w", err)
	}
	defer rows.Close()

	var out []models.DNSProviderRow
	for rows.Next() {
		var (
			r  models.DNSProviderRow
			en int
		)
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.CredentialsEncrypted, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetDNSProvider returns the row for name, or ErrDNSProviderNotFound.
func GetDNSProvider(ctx context.Context, d *sql.DB, name string) (models.DNSProviderRow, error) {
	var (
		r  models.DNSProviderRow
		en int
	)
	err := d.QueryRowContext(ctx,
		`SELECT id, name, enabled, credentials_encrypted, updated_at
		   FROM dns_providers
		  WHERE name = ?`, name).
		Scan(&r.ID, &r.Name, &en, &r.CredentialsEncrypted, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return models.DNSProviderRow{}, ErrDNSProviderNotFound
	}
	if err != nil {
		return models.DNSProviderRow{}, fmt.Errorf("get dns_provider %s: %w", name, err)
	}
	r.Enabled = en == 1
	return r, nil
}

// UpsertDNSProviderCredentials updates enabled + credentials_encrypted
// in one statement. The caller has already (a) filtered the creds map
// through dnsproviders.FilterKnownFields and (b) validated required
// fields via dnsproviders.ValidateCredentials -- this function is the
// storage step.
//
// Passing creds == nil is the "just toggle enabled, preserve existing
// credentials" path. Passing an empty (non-nil) map clears the blob.
func UpsertDNSProviderCredentials(
	ctx context.Context,
	d *sql.DB,
	cipher *crypto.Cipher,
	name string,
	enabled bool,
	creds map[string]string,
) error {
	if cipher == nil {
		return errors.New("dns provider: cipher not wired")
	}
	if _, err := dnsproviders.Get(name); err != nil {
		return err
	}

	// Preserve-existing path: update enabled only.
	if creds == nil {
		_, err := d.ExecContext(ctx,
			`UPDATE dns_providers
			    SET enabled = ?,
			        updated_at = CURRENT_TIMESTAMP
			  WHERE name = ?`,
			boolToInt(enabled), name,
		)
		if err != nil {
			return fmt.Errorf("update dns_provider enabled %s: %w", name, err)
		}
		return nil
	}

	// Replace-credentials path: marshal, encrypt, write. The
	// encrypted ciphertext is stored as a BLOB; crypto.Cipher returns
	// "argos1:<base64>" which we store as-is (bytes). Decryption
	// side tolerates both base64-wrapped and raw BLOB.
	raw, err := dnsproviders.EncodeCredentials(creds)
	if err != nil {
		return fmt.Errorf("encode creds: %w", err)
	}
	ct, err := cipher.Encrypt(string(raw))
	if err != nil {
		return fmt.Errorf("encrypt creds: %w", err)
	}

	_, err = d.ExecContext(ctx,
		`UPDATE dns_providers
		    SET enabled = ?,
		        credentials_encrypted = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE name = ?`,
		boolToInt(enabled), []byte(ct), name,
	)
	if err != nil {
		return fmt.Errorf("update dns_provider credentials %s: %w", name, err)
	}
	return nil
}

// ClearDNSProviderCredentials zeroes the blob and flips enabled off.
// Used by the down-migration-plus-rollback path and by explicit
// delete flows in the API.
func ClearDNSProviderCredentials(ctx context.Context, d *sql.DB, name string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE dns_providers
		    SET enabled = 0,
		        credentials_encrypted = NULL,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("clear dns_provider %s: %w", name, err)
	}
	return nil
}

// GetDecryptedDNSCredentials decrypts a row's credentials_encrypted
// into a map. Returns (nil, nil) when the row has no credentials
// stored (enabled=0 is possible even with creds, enabled=1 without
// creds is the "about to be configured" state). Errors on decrypt
// failure -- usually a changed ARGOS_MASTER_KEY.
func GetDecryptedDNSCredentials(
	ctx context.Context,
	d *sql.DB,
	cipher *crypto.Cipher,
	name string,
) (map[string]string, error) {
	if cipher == nil {
		return nil, errors.New("dns provider: cipher not wired")
	}
	r, err := GetDNSProvider(ctx, d, name)
	if err != nil {
		return nil, err
	}
	if len(r.CredentialsEncrypted) == 0 {
		return nil, nil
	}
	pt, err := cipher.Decrypt(string(r.CredentialsEncrypted))
	if err != nil {
		return nil, fmt.Errorf("decrypt dns_provider %s: %w", name, err)
	}
	return dnsproviders.DecodeCredentials([]byte(pt))
}

// DNSCredentialMap is the in-memory map the reconciler hands to the
// caddycfg generator: provider name -> decrypted credentials. Only
// enabled providers with non-empty credentials are included.
type DNSCredentialMap map[string]map[string]string

// LoadEnabledDNSCredentials hydrates the map the reconciler passes
// into caddycfg. One SELECT + N decrypts. Providers whose decrypt
// fails are logged by the caller if a slog.Handler is attached; this
// function returns an aggregate error so the caller can choose to
// reconcile partial state vs. abort.
func LoadEnabledDNSCredentials(
	ctx context.Context,
	d *sql.DB,
	cipher *crypto.Cipher,
) (DNSCredentialMap, error) {
	if cipher == nil {
		return nil, errors.New("dns provider: cipher not wired")
	}
	rows, err := ListDNSProviders(ctx, d)
	if err != nil {
		return nil, err
	}
	out := make(DNSCredentialMap, len(rows))
	var firstErr error
	for _, r := range rows {
		if !r.Enabled || len(r.CredentialsEncrypted) == 0 {
			continue
		}
		pt, derr := cipher.Decrypt(string(r.CredentialsEncrypted))
		if derr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("decrypt %s: %w", r.Name, derr)
			}
			continue
		}
		creds, derr := dnsproviders.DecodeCredentials([]byte(pt))
		if derr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("decode %s: %w", r.Name, derr)
			}
			continue
		}
		out[r.Name] = creds
	}
	return out, firstErr
}

// DNSProviderBase64Hint is an operator-visible helper that renders
// the encrypted blob as base64 for debug / audit output. Never used
// to decrypt; present so ad-hoc sqlite3 inspection does not show raw
// bytes. Not wired into the API.
func DNSProviderBase64Hint(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
