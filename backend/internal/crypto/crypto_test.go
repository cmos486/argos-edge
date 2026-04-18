package crypto

import (
	"encoding/base64"
	"testing"
)

func decodeForTest(enc string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(enc[len(Prefix):])
}

func encodeForTest(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func testKey(t *testing.T) string {
	t.Helper()
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func TestRoundTrip(t *testing.T) {
	c, err := New(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"hello", "bot-token:123:abc", "", "Authorization: Bearer xyz"}
	for _, pt := range cases {
		enc, err := c.Encrypt(pt)
		if err != nil {
			t.Fatalf("encrypt %q: %v", pt, err)
		}
		if pt == "" && enc != "" {
			t.Fatalf("empty plaintext should round-trip empty, got %q", enc)
		}
		if pt != "" && !IsEncrypted(enc) {
			t.Fatalf("expected argos1: prefix, got %q", enc)
		}
		got, err := c.Decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestBadKey(t *testing.T) {
	if _, err := New(""); err != ErrNoMasterKey {
		t.Fatalf("want ErrNoMasterKey, got %v", err)
	}
	if _, err := New("deadbeef"); err != ErrKeyBadLength {
		t.Fatalf("short key: want ErrKeyBadLength, got %v", err)
	}
	if _, err := New("nothex-nothex-nothex"); err == nil {
		t.Fatal("want hex decode error")
	}
}

func TestDecryptBadInput(t *testing.T) {
	c, _ := New(testKey(t))
	if _, err := c.Decrypt("cleartext"); err != ErrNotEncrypted {
		t.Fatalf("cleartext should be rejected, got %v", err)
	}
	if _, err := c.Decrypt(Prefix + "!!!not-base64!!!"); err == nil {
		t.Fatal("malformed base64 should fail")
	}
	if _, err := c.Decrypt(Prefix + "QUJD"); err != ErrBadCipherText {
		t.Fatalf("short ct: want ErrBadCipherText, got %v", err)
	}
}

func TestTamperDetect(t *testing.T) {
	c, _ := New(testKey(t))
	enc, _ := c.Encrypt("secret")
	// decode, flip a byte in the ciphertext body, re-encode so base64
	// itself remains valid and only the AEAD tag check catches it
	raw, err := decodeForTest(enc)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := Prefix + encodeForTest(raw)
	if _, err := c.Decrypt(tampered); err != ErrBadCipherText {
		t.Fatalf("tampered ct: want ErrBadCipherText, got %v", err)
	}
}
