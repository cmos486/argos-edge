// Package geoip enriches IP addresses with country + ASN data sourced
// from the DB-IP Lite CC-BY databases. Two .mmdb files live in
// /data/geoip (country.mmdb, asn.mmdb); a background downloader
// fetches them at first boot and refreshes monthly.
//
// Attribution note: DB-IP Lite is distributed under CC-BY. The UI
// MUST render a visible "IP geolocation by DB-IP" credit with a link
// to https://db-ip.com for the license to be respected. The backend
// includes a readable constant (AttributionText) that the frontend
// pulls through /api/geoip/status so the attribution survives even
// if someone removes it from the UI by accident.
package geoip

import "net"

// AttributionText is the CC-BY-required credit surfaced by the UI.
const AttributionText = "IP geolocation by DB-IP (https://db-ip.com)"

// IsPrivate reports whether the given IP is a private / non-routable
// address the geoip DBs would not have data for. Returning true
// short-circuits the mmdb lookup so we don't waste a read. Covers:
//
//   - RFC1918 (10/8, 172.16/12, 192.168/16)
//   - Loopback (127/8, ::1)
//   - Link-local IPv4 (169.254/16) + IPv6 (fe80::/10)
//   - CGNAT shared (100.64/10)
//   - IPv6 ULA (fc00::/7)
//   - Unspecified (0.0.0.0, ::)
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Go's stdlib already covers a lot.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// RFC1918
		for _, block := range v4Private {
			if block.Contains(v4) {
				return true
			}
		}
		// CGNAT 100.64.0.0/10
		if cgnatV4.Contains(v4) {
			return true
		}
		return false
	}
	// IPv6: ULA fc00::/7 covers fc00:: and fd00::
	if ulaV6.Contains(ip) {
		return true
	}
	return false
}

var (
	v4Private = []*net.IPNet{
		mustCIDR("10.0.0.0/8"),
		mustCIDR("172.16.0.0/12"),
		mustCIDR("192.168.0.0/16"),
	}
	cgnatV4 = mustCIDR("100.64.0.0/10")
	ulaV6   = mustCIDR("fc00::/7")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err) // programming error: hardcoded constants
	}
	return n
}
