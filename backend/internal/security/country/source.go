package country

import (
	"fmt"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// MMDBSource is the production CIDRSource. It opens the country
// MMDB file (DB-IP Lite shape, see backend/internal/geoip/lookup.go)
// per call and iterates every network, collecting those whose
// country.iso_code matches the requested code, then runs the raw
// list through RollupToSupernets to compress to <= RollupTarget
// CIDRs (default 200).
//
// The rollup is non-optional. v1.3.22 found that pushing the raw
// MMDB iteration to LAPI silently drops most entries under SQLite
// WAL lock contention -- BR's 21k+ raw CIDRs landed as ~5k IPv6-
// only entries with zero IPv4 coverage. The rollup keeps the row
// count well within LAPI's atomic-batch zone (one POST, <2s, no
// lock retries).
//
// RollupTarget=0 falls back to DefaultRollupTarget. Callers that
// want unmodified MMDB output (tests, debugging) should construct
// their own CIDRSource implementation rather than setting
// RollupTarget=-1 -- a too-large target risks reproducing the
// v1.3.22 SQLite-lock loss.
//
// SkipAliasedNetworks is set so the IPv4-in-IPv6 alias prefix
// (::ffff:0.0.0.0/96) does not produce duplicate entries.
type MMDBSource struct {
	Path         string // /data/geoip/country.mmdb
	RollupTarget int    // 0 = DefaultRollupTarget
}

// countryRecord matches DB-IP Lite's shape. The geoip package uses
// the same record under a different name; the duplication is fine
// here -- this struct is private to the iteration path.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// ListCIDRs implements CIDRSource. The country code MUST already be
// uppercased (Expander.Ban does this).
func (s *MMDBSource) ListCIDRs(countryCode string) ([]string, string, error) {
	r, err := maxminddb.Open(s.Path)
	if err != nil {
		return nil, "", fmt.Errorf("open mmdb %q: %w", s.Path, err)
	}
	defer r.Close()

	var rec countryRecord
	networks := r.Networks(maxminddb.SkipAliasedNetworks)
	cidrs := make([]string, 0, 256)
	for networks.Next() {
		subnet, err := networks.Network(&rec)
		if err != nil {
			return nil, "", fmt.Errorf("decode network: %w", err)
		}
		if rec.Country.ISOCode == countryCode {
			cidrs = append(cidrs, subnet.String())
		}
	}
	if err := networks.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate networks: %w", err)
	}

	version := time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format("2006-01")
	rolled := RollupToSupernets(cidrs, s.RollupTarget)
	return rolled, version, nil
}
