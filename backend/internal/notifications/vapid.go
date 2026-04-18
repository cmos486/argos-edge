package notifications

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// VAPIDSettingPublic + PublicKey and VAPIDSettingPrivate are the
// settings-table keys used to persist the generated VAPID keypair.
const (
	VAPIDSettingPublic  = "notifications.vapid_public_key"
	VAPIDSettingPrivate = "notifications.vapid_private_key"
	VAPIDSettingContact = "notifications.vapid_contact_email"
)

// VAPIDKeys is the resolved public/private pair with private decrypted
// into plaintext (base64 URL), ready for webpush-go calls.
type VAPIDKeys struct {
	Public  string
	Private string
	Contact string
}

// EnsureVAPID makes sure a keypair exists in settings. If missing,
// generates one with webpush-go, encrypts the private key with the
// master cipher, writes both back, and returns the pair.
//
// Called once at startup before the worker is wired.
func EnsureVAPID(ctx context.Context, d *sql.DB, c *crypto.Cipher) (*VAPIDKeys, error) {
	pub := db.GetSettingValue(ctx, d, VAPIDSettingPublic, "")
	privEnc := db.GetSettingValue(ctx, d, VAPIDSettingPrivate, "")
	contact := db.GetSettingValue(ctx, d, VAPIDSettingContact, "admin@example.com")

	if pub == "" || privEnc == "" {
		priv, pubGen, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			return nil, fmt.Errorf("generate vapid keys: %w", err)
		}
		encPriv, err := c.Encrypt(priv)
		if err != nil {
			return nil, fmt.Errorf("encrypt vapid private: %w", err)
		}
		if err := db.UpsertSetting(ctx, d, VAPIDSettingPublic, pubGen); err != nil {
			return nil, fmt.Errorf("save vapid public: %w", err)
		}
		if err := db.UpsertSetting(ctx, d, VAPIDSettingPrivate, encPriv); err != nil {
			return nil, fmt.Errorf("save vapid private: %w", err)
		}
		slog.Info("notifications: generated new VAPID keypair")
		return &VAPIDKeys{Public: pubGen, Private: priv, Contact: contact}, nil
	}

	priv, err := c.Decrypt(privEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt vapid private: %w", err)
	}
	return &VAPIDKeys{Public: pub, Private: priv, Contact: contact}, nil
}
