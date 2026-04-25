package country

import (
	"fmt"
	"net/netip"
	"testing"
)

// TestRollupSmallInputUnchanged: small CIDR sets that already fit
// the target budget pass through untouched (modulo set-vs-list
// ordering). Catches a future "always aggregate aggressively"
// regression that would over-coarsen small-country expansions.
func TestRollupSmallInputUnchanged(t *testing.T) {
	in := []string{
		"203.0.113.0/24",
		"198.51.100.0/24",
		"192.0.2.0/24",
	}
	out := RollupToSupernets(in, 200)
	if len(out) != 3 {
		t.Fatalf("expected 3 outputs (input fits budget), got %d: %v", len(out), out)
	}
	// Set membership: every input must appear unchanged in output.
	got := map[string]bool{}
	for _, s := range out {
		got[s] = true
	}
	for _, s := range in {
		if !got[s] {
			t.Fatalf("input %q missing from rollup output: %v", s, out)
		}
	}
}

// TestRollupCollapsesAdjacentPrefixes: two /24s that share a /23
// supernet should round-trip through that /23 once the budget
// forces aggregation.
func TestRollupCollapsesAdjacentPrefixes(t *testing.T) {
	in := []string{
		"203.0.112.0/24",
		"203.0.113.0/24", // adjacent: shares 203.0.112.0/23
	}
	out := RollupToSupernets(in, 1) // budget = 1 forces aggregation
	if len(out) != 1 {
		t.Fatalf("expected 1 output with budget=1, got %d: %v", len(out), out)
	}
	// 203.0.112.0/23 is the smallest supernet containing both.
	// The algorithm walks /32 -> /0; first prefix length that
	// dedupes the two inputs to one supernet is /23.
	if out[0] != "203.0.112.0/23" {
		t.Fatalf("expected /23 supernet, got %q", out[0])
	}
}

// TestRollupCoversAllInputAddresses: an aggressively rolled-up
// supernet set must STILL contain every IP that was in the
// original input. Loss of precision = supernets cover MORE
// territory, not less. This is the operator-trust invariant:
// "ban country BR" must continue to block IPs that were in BR
// per the MMDB even if collateral over-blocking is acceptable.
func TestRollupCoversAllInputAddresses(t *testing.T) {
	// 200 random-ish /24s spread within 10.0.0.0/8 (a single /8 so
	// rollup can fit the budget without crossing the MinV4Prefix
	// floor). budget=10 is impossible at /16 (would need 256
	// distinct /16s in one /8 -- impossible) so the algorithm
	// returns at the floor. Coverage check still must hold.
	var in []string
	for i := 0; i < 200; i++ {
		in = append(in, fmt.Sprintf("10.%d.0.0/24", i))
	}
	out := RollupToSupernets(in, 10)
	// Note: budget may be exceeded if the floor is hit. The
	// invariant is coverage, not strict count compliance.
	if len(out) > 256 {
		t.Fatalf("output count blew past /16 floor (256 max for one /8): %d", len(out))
	}

	// Coverage check: pick a representative IP from each input
	// /24 and verify some output supernet contains it.
	supernets := make([]netip.Prefix, 0, len(out))
	for _, s := range out {
		p, _ := netip.ParsePrefix(s)
		supernets = append(supernets, p)
	}
	for _, s := range in {
		inputPrefix, _ := netip.ParsePrefix(s)
		// pick the network address as the representative IP
		ip := inputPrefix.Addr()
		covered := false
		for _, sup := range supernets {
			if sup.Contains(ip) {
				covered = true
				break
			}
		}
		if !covered {
			t.Fatalf("input %q (rep IP %s) not covered by any output supernet: %v",
				s, ip, out)
		}
	}
}

// TestRollupBRSizeSimulation: simulate a country-sized input
// and assert the output stays within the operator-trust floor
// AND no supernet wider than MinV4Prefix is produced. The /6
// over-blocking incident from v1.3.22 prod-smoke (1.1.1.1 hit
// by a 0.0.0.0/6 BR rollup) is the regression locked here.
func TestRollupBRSizeSimulation(t *testing.T) {
	var in []string
	// IPv4: 200 distinct /16s, each contributing ~100 /24s.
	// 200 * 100 = 20,000 IPv4 entries, scattered over 200 /16s.
	for second := 0; second < 200; second++ {
		for third := 0; third < 100; third++ {
			in = append(in, fmt.Sprintf("203.%d.%d.0/24", second%256, third))
		}
	}
	for i := 0; i < 1000; i++ {
		in = append(in, fmt.Sprintf("2001:%x::/32", 0xdb80+i))
	}

	out := RollupToSupernets(in, DefaultRollupTarget)
	if len(out) < 5 {
		t.Fatalf("rollup over-aggressive, got only %d outputs: %v", len(out), out)
	}
	// Hard floor on supernet width: every output prefix must be
	// >= MinV4Prefix (v4) or >= MinV6Prefix (v6). Catches the
	// "/6 supernet" prod incident.
	for _, s := range out {
		p, _ := netip.ParsePrefix(s)
		if p.Addr().Is4() && p.Bits() < MinV4Prefix {
			t.Fatalf("v4 supernet %q wider than floor /%d", s, MinV4Prefix)
		}
		if p.Addr().Is6() && p.Bits() < MinV6Prefix {
			t.Fatalf("v6 supernet %q wider than floor /%d", s, MinV6Prefix)
		}
	}
}

// TestRollupRespectsV4Floor: a fixture that would otherwise
// roll up to /6 must instead stop at /16 even if the budget
// is unreachable. v1.3.22 prod-smoke caught this: 50 random
// /24s scattered across 50 distant /8s, budget=10. Pre-fix
// algorithm widened to /6 (over-blocking 8.8.8.8). Post-fix
// must return ~50 /16s and exceed budget rather than violate
// the floor.
func TestRollupRespectsV4Floor(t *testing.T) {
	var in []string
	for i := 0; i < 50; i++ {
		// Each /24 is in a distant /8 -- impossible to merge into
		// fewer than 50 /16s without crossing the floor.
		in = append(in, fmt.Sprintf("%d.0.0.0/24", i+10))
	}
	out := RollupToSupernets(in, 10) // budget impossibly small
	for _, s := range out {
		p, _ := netip.ParsePrefix(s)
		if p.Bits() < MinV4Prefix {
			t.Fatalf("v4 supernet %q crossed floor /%d (over-blocking risk)",
				s, MinV4Prefix)
		}
	}
	// Coverage must still hold for every input.
	supernets := make([]netip.Prefix, 0, len(out))
	for _, s := range out {
		p, _ := netip.ParsePrefix(s)
		supernets = append(supernets, p)
	}
	for _, s := range in {
		ip, _ := netip.ParsePrefix(s)
		covered := false
		for _, sup := range supernets {
			if sup.Contains(ip.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			t.Fatalf("input %q not covered after floor-bounded rollup", s)
		}
	}
}

// TestRollupSplitsIPv4AndIPv6: the per-family budget split (half
// for v4, half for v6) means a 50/50 input set produces roughly
// 50/50 output. Exercises the family-aware aggregation rather
// than treating both families as one bucket.
func TestRollupSplitsIPv4AndIPv6(t *testing.T) {
	in := []string{
		"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
		"2001:db8::/32", "2001:db9::/32", "2001:dba::/32", "2001:dbb::/32",
	}
	out := RollupToSupernets(in, 200) // generous budget
	v4Count := 0
	v6Count := 0
	for _, s := range out {
		p, _ := netip.ParsePrefix(s)
		if p.Addr().Is4() {
			v4Count++
		} else {
			v6Count++
		}
	}
	if v4Count == 0 {
		t.Fatalf("expected IPv4 entries in output, got none: %v", out)
	}
	if v6Count == 0 {
		t.Fatalf("expected IPv6 entries in output, got none: %v", out)
	}
}

// TestRollupEmptyInput: zero CIDRs in -> zero CIDRs out. Caller
// (Expander.Ban) will then surface ErrCountryNotFound; rollup
// itself shouldn't error or panic.
func TestRollupEmptyInput(t *testing.T) {
	out := RollupToSupernets(nil, 200)
	if len(out) != 0 {
		t.Fatalf("empty input should yield empty output, got %v", out)
	}
}

// TestRollupSkipsMalformed: a malformed CIDR string is dropped
// silently rather than aborting the whole rollup. The upstream
// MMDB iterator never produces malformed prefixes today, but
// future callers (e.g., operator-supplied lists in v1.3.23+)
// might.
func TestRollupSkipsMalformed(t *testing.T) {
	in := []string{"not-a-cidr", "203.0.113.0/24", "also/garbage", "198.51.100.0/24"}
	out := RollupToSupernets(in, 200)
	if len(out) != 2 {
		t.Fatalf("expected 2 valid outputs, got %d: %v", len(out), out)
	}
}
