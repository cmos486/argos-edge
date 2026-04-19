package totp

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// QRPixelSize is the default PNG side length. 256 px is small enough
// to inline in a modal (~7 KiB base64) and large enough to scan with
// a phone held at arm's length.
const QRPixelSize = 256

// GeneratePNG renders the otpauth:// URL as a PNG byte slice. Medium
// recovery level keeps the code scannable after a screenshot compress
// or a laptop-screen glare without bloating the payload.
//
// Returned bytes should be served either as image/png directly or
// base64-encoded inside a JSON response. The API layer picks the
// latter so the frontend does not need to fetch a second resource
// or handle a separate image stream.
func GeneratePNG(otpauthURL string) ([]byte, error) {
	if otpauthURL == "" {
		return nil, fmt.Errorf("empty otpauth URL")
	}
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, QRPixelSize)
	if err != nil {
		return nil, fmt.Errorf("qrcode encode: %w", err)
	}
	return png, nil
}
