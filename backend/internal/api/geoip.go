package api

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/geoip"
)

// enrichIP looks up an IP via the GeoDB + Cache and returns a
// geoip.Result or nil when the subsystem is not wired. Private IPs
// short-circuit in geoip.Lookup; the cache answers repeats. Used by
// every batch enrichment path below so they share the same LRU.
func (h *Handlers) enrichIP(ip string) *geoip.Result {
	if h.GeoDB == nil {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return nil
	}
	if h.GeoCache != nil {
		if v, ok := h.GeoCache.Get(ip); ok {
			vv := v
			return &vv
		}
	}
	res := h.GeoDB.Lookup(ip)
	if h.GeoCache != nil {
		h.GeoCache.Put(ip, res)
	}
	return &res
}

// toDashboardGeo + toThreatsGeo flatten a *geoip.Result into the
// sibling type declared in each consumer package (so those packages
// stay free of a geoip import). Returns nil if the input is nil.
func toDashboardGeo(r *geoip.Result) *dashboard.GeoEnrichment {
	if r == nil {
		return nil
	}
	return &dashboard.GeoEnrichment{
		CountryCode: r.CountryCode,
		CountryName: r.CountryName,
		ASN:         r.ASN,
		ASNOrg:      r.ASNOrg,
		IsPrivate:   r.IsPrivate,
	}
}

func toThreatsGeo(r *geoip.Result) *crowdsec.GeoEnrichment {
	if r == nil {
		return nil
	}
	return &crowdsec.GeoEnrichment{
		CountryCode: r.CountryCode,
		CountryName: r.CountryName,
		ASN:         r.ASN,
		ASNOrg:      r.ASNOrg,
		IsPrivate:   r.IsPrivate,
	}
}

// requireGeoIP guards the endpoints against a panel booted without
// the geoip subsystem (defensive: main.go always wires it, but nil
// is possible in standalone test binaries).
func (h *Handlers) requireGeoIP(w http.ResponseWriter) bool {
	if h.GeoDB == nil {
		writeError(w, http.StatusServiceUnavailable, "geoip not wired")
		return false
	}
	return true
}

// GeoLookup GET /api/geoip/lookup?ip=X.X.X.X
//
// Auth: inherits the authed group (same as every other /api/* route).
// Cache: the LRU answers repeat hits. Private / unparseable IPs never
// hit the mmdb at all (short-circuit in geoip.Lookup).
func (h *Handlers) GeoLookup(w http.ResponseWriter, r *http.Request) {
	if !h.requireGeoIP(w) {
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip query parameter required")
		return
	}
	// Cheap validation so pathological strings do not end up as cache keys.
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	if h.GeoCache != nil {
		if v, ok := h.GeoCache.Get(ip); ok {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	res := h.GeoDB.Lookup(ip)
	if h.GeoCache != nil {
		h.GeoCache.Put(ip, res)
	}
	writeJSON(w, http.StatusOK, res)
}

// geoStatus is the shape /api/geoip/status returns. It merges
// DB-side metadata (versions, file sizes, last refresh telemetry)
// with cache-side counters for the UI status card.
type geoStatus struct {
	geoip.Status
	CacheSize   int    `json:"cache_size"`
	CacheHits   uint64 `json:"cache_hits"`
	CacheMisses uint64 `json:"cache_misses"`
}

// GeoStatus GET /api/geoip/status
func (h *Handlers) GeoStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireGeoIP(w) {
		return
	}
	out := geoStatus{Status: h.GeoDB.Status()}
	if h.GeoCache != nil {
		out.CacheSize = h.GeoCache.Size()
		out.CacheHits = h.GeoCache.Hits()
		out.CacheMisses = h.GeoCache.Misses()
	}
	writeJSON(w, http.StatusOK, out)
}

// GeoRefresh POST /api/geoip/refresh
//
// Triggers an on-demand DB-IP Lite pull. Bounded to 60s: the zipped
// mmdb files run <10 MiB combined, so the real budget is download
// speed. On success the cache is invalidated so the next Lookup
// hits the refreshed data; on failure the /api/geoip/status error
// field is populated and a 502 is returned.
//
// Every call -- success or failure -- emits an audit row
// ("update geoip_db") so the operator can trace who triggered it.
func (h *Handlers) GeoRefresh(w http.ResponseWriter, r *http.Request) {
	if !h.requireGeoIP(w) {
		return
	}
	if h.GeoDownloader == nil {
		writeError(w, http.StatusServiceUnavailable, "geoip downloader not wired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err := h.GeoDownloader.RefreshAll(ctx)
	st := h.GeoDB.Status()
	resp := map[string]any{
		"ok":              err == nil,
		"country_version": st.CountryDBVersion,
		"asn_version":     st.ASNDBVersion,
		"loaded_at":       st.LoadedAt,
		"last_refresh_at": st.LastRefreshAt,
		"country_db_size": st.CountryDBSize,
		"asn_db_size":     st.ASNDBSize,
	}
	diff := map[string]any{
		"event":           "geoip_db_updated",
		"ok":              err == nil,
		"country_version": st.CountryDBVersion,
		"asn_version":     st.ASNDBVersion,
	}
	if err != nil {
		resp["error"] = err.Error()
		diff["error"] = err.Error()
		h.audit(r, "update", "geoip_db", 0, diff)
		writeJSON(w, http.StatusBadGateway, resp)
		return
	}
	if h.GeoCache != nil {
		h.GeoCache.Invalidate()
	}
	h.audit(r, "update", "geoip_db", 0, diff)
	writeJSON(w, http.StatusOK, resp)
}
