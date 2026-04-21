package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
)

// ImportLegacyCloudflareToken is the v1.3 upgrade path for operators
// who have CLOUDFLARE_API_TOKEN set on the panel / caddy container.
// If the cloudflare dns_providers row is empty (no credentials, or
// missing entirely), the env token is encrypted and persisted so the
// reconciler can start serving it via Option 2. The cloudflare row
// is flipped enabled=1 at the same time.
//
// Idempotent: if the row already has credentials, nothing is done.
// Safe to call on every boot.
//
// The function does not REMOVE the env var; the operator owns .env
// rotation. A one-shot INFO log line advises that the env can be
// removed at the next convenience.
func ImportLegacyCloudflareToken(ctx context.Context, d *sql.DB, cipher *crypto.Cipher) error {
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		return nil
	}
	if cipher == nil {
		return errors.New("cloudflare token import: cipher not wired")
	}

	row, err := GetDNSProvider(ctx, d, "cloudflare")
	if err != nil && !errors.Is(err, ErrDNSProviderNotFound) {
		return fmt.Errorf("cloudflare token import: lookup: %w", err)
	}
	// Row already has credentials? nothing to do.
	if err == nil && len(row.CredentialsEncrypted) > 0 {
		return nil
	}

	creds := map[string]string{"api_token": token}
	if err := UpsertDNSProviderCredentials(ctx, d, cipher, "cloudflare", true, creds); err != nil {
		return fmt.Errorf("cloudflare token import: upsert: %w", err)
	}
	slog.Info("dns_provider: imported CLOUDFLARE_API_TOKEN env var into encrypted DB; you may remove it from .env at your next restart")
	return nil
}
