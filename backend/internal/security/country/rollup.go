package country

import (
	"net/netip"
)

// DefaultRollupTarget is the default upper bound on the number of
// CIDR ranges any one country expands to. v1.3.22 introduced the
// rollup after empirical testing showed that pushing 21k+ raw
// CIDRs (BR's full DB-IP Lite footprint) to LAPI silently dropped
// most of them under SQLite WAL lock contention. 200 is small
// enough to land atomically in one /v1/alerts batch (<1MB body,
// <2s LAPI processing) and large enough to keep the precision
// loss bearable at typical IPv4-/16 / IPv6-/28 supernet sizes.
const DefaultRollupTarget = 200

// MinV4Prefix bounds how aggressively the rollup widens IPv4
// supernets. v4 /16 = 65k IPs, typically owned by one
// organisation in one country. /14 already spans multiple
// countries; /12 spans continents. v1.3.22 shipped without this
// floor and the algorithm widened to /6 (64M IPs) for BR,
// over-blocking 1.1.1.1 (US Cloudflare) under the BR ban.
const MinV4Prefix = 16

// MinV6Prefix is the equivalent floor for IPv6. v6 /28 keeps
// supernets within a typical /29 RIR allocation; widening below
// risks over-blocking other RIRs.
const MinV6Prefix = 28

// RollupToSupernets compresses a list of CIDR ranges into at most
// `target` supernets, accepting some loss of precision in exchange
// for atomicity and operator-friendly counts.
//
// The compression is family-split: half the budget for IPv4, half
// for IPv6. Within each family, the algorithm picks the LONGEST
// (most specific) prefix length that yields <= half-target distinct
// supernets after truncation. v4 prefixes never widen below /0 and
// v6 prefixes never widen below /0; the algorithm always
// terminates.
//
// Trade-off: a country whose IPv4 footprint is scattered across
// many distant /16s collapses to fewer, wider supernets that may
// over-cover (block legitimate non-country traffic in the same
// /14 or /12). Operators wanting tighter precision can still use
// raw cscli decisions for individual IPs / Ranges; the country-
// expansion path is "approximately ban this country, atomically".
//
// target=0 falls back to DefaultRollupTarget. Empty input returns
// nil. Malformed CIDRs are skipped silently (the upstream MMDB
// iterator never produces malformed entries; this is defence in
// depth for future callers that pass operator-supplied input).
func RollupToSupernets(cidrs []string, target int) []string {
	if target <= 0 {
		target = DefaultRollupTarget
	}
	if len(cidrs) == 0 {
		return nil
	}

	var v4, v6 []netip.Prefix
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		// Normalise to canonical form so later comparisons via the
		// netip.Prefix map key behave correctly.
		p = p.Masked()
		// Networks(SkipAliasedNetworks) shouldn't return v6-mapped
		// v4 entries, but if a future caller does, treat them as v4.
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}

	// Per-family budget: even split. If one family is empty the
	// other gets the full target.
	v4Budget := target / 2
	v6Budget := target / 2
	if len(v4) == 0 {
		v6Budget = target
	} else if len(v6) == 0 {
		v4Budget = target
	}

	v4 = aggregateToTarget(v4, v4Budget, 32, MinV4Prefix)
	v6 = aggregateToTarget(v6, v6Budget, 128, MinV6Prefix)

	out := make([]string, 0, len(v4)+len(v6))
	for _, p := range v4 {
		out = append(out, p.String())
	}
	for _, p := range v6 {
		out = append(out, p.String())
	}
	return out
}

// aggregateToTarget picks the longest prefix length that yields
// <= target distinct supernets after truncation. The walk goes
// from maxBits down to minBits; the first length whose dedup
// count fits the budget wins. If no length in [minBits, maxBits]
// fits, returns the result AT minBits even if it exceeds target.
//
// minBits is the over-coverage floor: a /16 v4 supernet is wide
// but plausibly contained to one country, while /6 spans
// continents. Trading "exceeded target" for "stayed within /16"
// is the safer call -- LAPI accepts the overage in one chunked
// batch, but customers don't accept being banned because the
// panel rolled up to /6.
//
// Time: O(N * (maxBits - minBits)). For BR (~21k inputs at
// maxBits=32, minBits=16) that's ~340k Prefix-mask ops,
// completes in under 30ms on a homelab box.
func aggregateToTarget(prefixes []netip.Prefix, target, maxBits, minBits int) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	if target <= 0 {
		target = 1
	}
	var lastSeen map[netip.Prefix]struct{}
	for bits := maxBits; bits >= minBits; bits-- {
		seen := make(map[netip.Prefix]struct{}, len(prefixes))
		for _, p := range prefixes {
			tb := bits
			if p.Bits() < tb {
				tb = p.Bits()
			}
			super := netip.PrefixFrom(p.Addr(), tb).Masked()
			seen[super] = struct{}{}
		}
		lastSeen = seen
		if len(seen) <= target {
			break
		}
	}
	out := make([]netip.Prefix, 0, len(lastSeen))
	for p := range lastSeen {
		out = append(out, p)
	}
	return out
}
