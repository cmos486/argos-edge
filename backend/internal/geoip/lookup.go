package geoip

import (
	"net"
	"time"
)

// Result is the enrichment the panel ships back to the UI. When the
// IP is private, only IP + IsPrivate + CountryName ("LAN") are set.
type Result struct {
	IP          string    `json:"ip"`
	IsPrivate   bool      `json:"is_private"`
	CountryCode string    `json:"country_code,omitempty"`
	CountryName string    `json:"country_name,omitempty"`
	ASN         uint      `json:"asn,omitempty"`
	ASNOrg      string    `json:"asn_org,omitempty"`
	LookedUpAt  time.Time `json:"looked_up_at"`
}

// countryRecord mirrors DB-IP Lite country.mmdb's data shape. We ask
// for English; DB-IP ships multiple locales.
type countryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// asnRecord mirrors DB-IP Lite asn.mmdb. Field names here are the
// canonical MaxMind / DB-IP ASN keys.
type asnRecord struct {
	ASN    uint   `maxminddb:"autonomous_system_number"`
	ASNOrg string `maxminddb:"autonomous_system_organization"`
}

// Lookup resolves IP → Result. Always cheap: private addresses are
// short-circuited; DBs are read-locked for ~microseconds; any error
// from the mmdb layer degrades to an Unknown result rather than
// propagating (the UI would have nowhere to surface it).
//
// The caller supplies the IP in either string form (parsed here) or
// via LookupIP with a pre-parsed net.IP.
func (d *DB) Lookup(ipStr string) Result {
	res := Result{IP: ipStr, LookedUpAt: time.Now().UTC()}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		res.CountryName = "Unknown"
		return res
	}
	return d.LookupIP(parsed)
}

// LookupIP is the net.IP variant used internally by the watcher /
// Top Attack IP enrichment path to skip a string round-trip.
func (d *DB) LookupIP(ip net.IP) Result {
	res := Result{IP: ip.String(), LookedUpAt: time.Now().UTC()}
	if IsPrivate(ip) {
		res.IsPrivate = true
		res.CountryName = "LAN"
		return res
	}
	d.mu.RLock()
	country := d.country
	asn := d.asn
	d.mu.RUnlock()

	if country == nil && asn == nil {
		res.CountryName = "Unknown"
		return res
	}
	if country != nil {
		var rec countryRecord
		if err := country.Lookup(ip, &rec); err == nil {
			res.CountryCode = rec.Country.ISOCode
			if n, ok := rec.Country.Names["en"]; ok {
				res.CountryName = n
			} else {
				res.CountryName = rec.Country.ISOCode
			}
		}
	}
	if asn != nil {
		var rec asnRecord
		if err := asn.Lookup(ip, &rec); err == nil {
			res.ASN = rec.ASN
			res.ASNOrg = rec.ASNOrg
		}
	}
	if res.CountryName == "" && res.ASNOrg == "" {
		res.CountryName = "Unknown"
	}
	return res
}
