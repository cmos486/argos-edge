// Package crypto wraps AES-GCM with a master key loaded from env so
// that secret fields (SMTP passwords, bot tokens, webhook auth headers,
// VAPID private key) can be persisted in SQLite without leaking them
// on disk.
//
// The master key is expected as 64 hex chars (32 bytes). Rotate it by
// decrypting all secrets, updating the env var, then re-encrypting --
// there is no key-id envelope in phase 5.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Unchanged is the sentinel the frontend sends back in a PUT when a
// user did not touch a secret field -- the backend must keep the
// previously-persisted ciphertext instead of re-encrypting this value.
const Unchanged = "__UNCHANGED__"

// Prefix marks a string as an argos-encrypted blob. Ciphertexts are
// "argos1:" + base64(nonce||ciphertext||tag). The prefix lets us
// round-trip encrypted + unencrypted values through the same JSON
// config fields without needing a separate column per secret.
const Prefix = "argos1:"

var (
	ErrNoMasterKey     = errors.New("master key not configured")
	ErrBadCipherText   = errors.New("ciphertext is malformed or tampered")
	ErrNotEncrypted    = errors.New("value is not an argos-encrypted blob")
	ErrKeyBadLength    = errors.New("master key must be 32 bytes (64 hex chars)")
)

// Cipher is a handle to an AES-GCM instance bound to the master key.
type Cipher struct {
	aead cipher.AEAD
}

// New parses the hex-encoded master key and returns a reusable Cipher.
// Safe for concurrent use: AEAD is goroutine-safe.
func New(masterKeyHex string) (*Cipher, error) {
	if masterKeyHex == "" {
		return nil, ErrNoMasterKey
	}
	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, ErrKeyBadLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt returns a prefixed base64 blob. Empty plaintext is passed
// through unchanged so callers do not have to special-case empty
// secrets.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ct := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	blob := append(nonce, ct...)
	return Prefix + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt is the inverse of Encrypt. Empty input returns empty. Non-
// prefixed input is rejected with ErrNotEncrypted.
func (c *Cipher) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if len(encoded) <= len(Prefix) || encoded[:len(Prefix)] != Prefix {
		return "", ErrNotEncrypted
	}
	raw, err := base64.StdEncoding.DecodeString(encoded[len(Prefix):])
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns+c.aead.Overhead() {
		return "", ErrBadCipherText
	}
	nonce := raw[:ns]
	ct := raw[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrBadCipherText
	}
	return string(pt), nil
}

// IsEncrypted reports whether s looks like an argos-encrypted blob.
// Useful when round-tripping JSON config where a field may hold either
// a fresh plaintext (create), an existing ciphertext (read/update),
// or the Unchanged sentinel (partial update).
func IsEncrypted(s string) bool {
	return len(s) > len(Prefix) && s[:len(Prefix)] == Prefix
}
