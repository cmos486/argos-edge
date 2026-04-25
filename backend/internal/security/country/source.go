package country

import (
	"fmt"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// MMDBSource is the production CIDRSource. It opens the country
// MMDB file (DB-IP Lite shape, see backend/internal/geoip/lookup.go)
// per call and iterates every network, collecting those whose
// country.iso_code matches the requested code.
//
// Iteration is O(N) over all networks (~400-600k entries); on a
// modern host it completes in 100-300 ms. Country expansion is an
// operator-rare action -- ban a country once, the rest is LAPI --
// so we open + iterate + close per call rather than holding a
// long-lived reader.
//
// SkipAliasedNetworks is set so the IPv4-in-IPv6 alias prefix
// (::ffff:0.0.0.0/96) does not produce duplicate entries.
type MMDBSource struct {
	Path string // /data/geoip/country.mmdb
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
	return cidrs, version, nil
}
