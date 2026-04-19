package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLookupPrivate covers the short-circuit path: a DB with no
// readers should still correctly answer private IPs with IsPrivate=true,
// CountryName="LAN" and leave ASN fields empty.
func TestLookupPrivate(t *testing.T) {
	db := NewDB(t.TempDir())
	// intentionally do NOT load any .mmdb
	cases := []string{
		"192.168.1.1", "10.1.2.3", "172.16.0.1",
		"127.0.0.1", "169.254.1.1", "100.64.0.1",
		"::1", "fe80::1", "fc00::1", "fd00::1",
	}
	for _, ipStr := range cases {
		r := db.Lookup(ipStr)
		if !r.IsPrivate {
			t.Errorf("%s: IsPrivate = false, want true", ipStr)
		}
		if r.CountryName != "LAN" {
			t.Errorf("%s: CountryName = %q, want \"LAN\"", ipStr, r.CountryName)
		}
		if r.ASN != 0 || r.ASNOrg != "" {
			t.Errorf("%s: ASN fields should be empty on private; got %d / %q",
				ipStr, r.ASN, r.ASNOrg)
		}
	}
}

// TestLookupWithoutDB verifies a public IP returns CountryName=Unknown
// when no DB is loaded -- we must degrade gracefully, never panic.
func TestLookupWithoutDB(t *testing.T) {
	db := NewDB(t.TempDir())
	r := db.Lookup("8.8.8.8")
	if r.IsPrivate {
		t.Fatal("8.8.8.8 should not be private")
	}
	if r.CountryName != "Unknown" {
		t.Errorf("CountryName = %q, want \"Unknown\"", r.CountryName)
	}
}

// TestLookupInvalidIP ensures unparseable input doesn't crash.
func TestLookupInvalidIP(t *testing.T) {
	db := NewDB(t.TempDir())
	r := db.Lookup("not-an-ip")
	if r.CountryName != "Unknown" {
		t.Errorf("garbage IP should yield Unknown, got %q", r.CountryName)
	}
}

// TestLookupRealIPs is the spec's "tests unitarios Lookup con IPs de
// verdad" path. It only runs when the mmdb files exist on disk (a
// CI environment or a dev box that's already pulled DB-IP Lite).
// Runs against /data/geoip by default; override via GEOIP_TEST_DIR.
func TestLookupRealIPs(t *testing.T) {
	dir := os.Getenv("GEOIP_TEST_DIR")
	if dir == "" {
		dir = "/data/geoip"
	}
	country := filepath.Join(dir, "country.mmdb")
	asn := filepath.Join(dir, "asn.mmdb")
	if _, err := os.Stat(country); err != nil {
		t.Skipf("skip: %s missing (run the stack or set GEOIP_TEST_DIR)", country)
	}
	if _, err := os.Stat(asn); err != nil {
		t.Skipf("skip: %s missing", asn)
	}
	db := NewDB(dir)
	if err := db.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	cases := []struct {
		ip            string
		wantCountry   string // ISO-2 or "" to skip this assertion
		wantASN       uint
		wantOrgSubstr string // case-insensitive substring, "" to skip
	}{
		{"8.8.8.8", "US", 15169, "google"},
		{"1.1.1.1", "", 13335, "cloudflare"},
		{"2606:4700:4700::1111", "", 13335, "cloudflare"},
	}
	for _, c := range cases {
		r := db.Lookup(c.ip)
		if r.IsPrivate {
			t.Errorf("%s: IsPrivate=true, want public", c.ip)
			continue
		}
		if c.wantCountry != "" && r.CountryCode != c.wantCountry {
			t.Errorf("%s: CountryCode = %q, want %q", c.ip, r.CountryCode, c.wantCountry)
		}
		if c.wantASN > 0 && r.ASN != c.wantASN {
			t.Errorf("%s: ASN = %d, want %d", c.ip, r.ASN, c.wantASN)
		}
		if c.wantOrgSubstr != "" && !strings.Contains(strings.ToLower(r.ASNOrg), c.wantOrgSubstr) {
			t.Errorf("%s: ASNOrg = %q, want substring %q", c.ip, r.ASNOrg, c.wantOrgSubstr)
		}
	}

	// Private IP behaviour against a loaded DB is identical to the
	// no-DB case -- short-circuit still applies.
	if r := db.Lookup("192.168.1.1"); !r.IsPrivate || r.CountryName != "LAN" {
		t.Errorf("192.168.1.1 on loaded DB: %+v (want LAN private)", r)
	}

	// LookupIP round-trip with a net.IP object.
	if r := db.LookupIP(net.ParseIP("8.8.8.8")); r.CountryCode != "US" {
		t.Errorf("LookupIP path: %+v", r)
	}
}
