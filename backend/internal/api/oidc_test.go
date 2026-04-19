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
	h := testHandlers(t, "argos.cmos486.es", "cmos486.es")
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
		{"panel host OK", "https://argos.cmos486.es/threats", "https://argos.cmos486.es/threats"},
		{"subdomain of parent OK", "https://huntlo.cmos486.es/page", "https://huntlo.cmos486.es/page"},
		{"parent itself OK", "https://cmos486.es/", "https://cmos486.es/"},
		{"external host blocked", "https://evil.com/malicious", "/"},
		{"parent suffix trickery blocked", "https://evilcmos486.es/", "/"},
		{"unparsable falls back", "ht!tp://??", "/"},
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
	h := testHandlers(t, "argos.cmos486.es", "")
	cases := []struct {
		in   string
		want string
	}{
		{"https://argos.cmos486.es/x", "https://argos.cmos486.es/x"},
		{"https://huntlo.cmos486.es/y", "/"}, // NOT allowed without parent
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
