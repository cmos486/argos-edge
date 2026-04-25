package api

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// testHandlers builds a Handlers with a :memory: DB seeded with
// just the one oidc.cookie_parent_domain setting the safeReturnTo
// validator reads.
func testHandlers(t *testing.T, panelDomain, parent string) *Handlers {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`CREATE TABLE settings (
		key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO settings(key, value) VALUES('oidc.cookie_parent_domain', ?)`, parent); err != nil {
		t.Fatal(err)
	}
	return &Handlers{DB: d, PanelDomain: panelDomain}
}

func TestSafeReturnTo(t *testing.T) {
	h := testHandlers(t, "app.example.com", "example.com")
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty -> root", "", "/"},
		{"relative path", "/dashboard", "/dashboard"},
		{"relative query", "/hosts?id=1", "/hosts?id=1"},
		// //protocol-relative is treated as external; spec says fall back.
		{"protocol-relative blocked", "//evil.com", "/"},
		{"panel host OK", "https://app.example.com/threats", "https://app.example.com/threats"},
		{"subdomain of parent OK", "https://marketplace.example.com/page", "https://marketplace.example.com/page"},
		{"parent itself OK", "https://example.com/", "https://example.com/"},
		{"external host blocked", "https://evil.com/malicious", "/"},
		{"parent suffix trickery blocked", "https://evilexample.com/", "/"},
		{"unparsable falls back", "ht!tp://??", "/"},
		// Browsers normalise "\" to "/" before issuing the network
		// request, so a literal "/\evil.com" bypasses the HasPrefix("//")
		// check and becomes "//evil.com" at navigation time. The
		// relative-path branch has to reject it outright.
		{"backslash literal", `/\evil.com/x`, "/"},
		{"double backslash", `/\\evil.com/x`, "/"},
		{"backslash at end", `/dashboard\`, "/"},
		// URL-encoded backslash lands at the browser as "\" after
		// percent-decoding, same outcome as the literal form.
		{"percent-encoded backslash lower", "/%5cevil.com/x", "/"},
		{"percent-encoded backslash upper", "/%5Cevil.com/x", "/"},
		// Control characters inside what would otherwise look like a
		// relative path are log-injection / header-smuggling payloads.
		{"null byte in path", "/dashboard\x00evil", "/"},
		{"carriage return", "/dashboard\revil", "/"},
		{"linefeed", "/dashboard\nevil", "/"},
		{"delete byte", "/dashboard\x7fevil", "/"},
		// Positive controls: legitimate relative paths must still pass
		// the hardened check.
		{"relative with query", "/dashboard?id=1", "/dashboard?id=1"},
		{"relative with fragment", "/hosts#top", "/hosts#top"},
		{"relative percent-encoded non-backslash", "/search?q=hello%20world", "/search?q=hello%20world"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.safeReturnTo(context.Background(), tc.in)
			if got != tc.want {
				t.Fatalf("safeReturnTo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSafeReturnToNoParent(t *testing.T) {
	// With no parent domain configured the only accepted absolute
	// URL is the panel's own host; subdomains fall back.
	h := testHandlers(t, "app.example.com", "")
	cases := []struct {
		in   string
		want string
	}{
		{"https://app.example.com/x", "https://app.example.com/x"},
		{"https://marketplace.example.com/y", "/"}, // NOT allowed without parent
		{"/dashboard", "/dashboard"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := h.safeReturnTo(context.Background(), tc.in)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
