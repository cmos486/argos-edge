package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/security"
	"github.com/cmos486/argos-edge/backend/internal/session"
)

// v1.3.19 introduces three minimal /api/security/* endpoints that
// support the self-block escape-hatch UI:
//
//   GET  /api/security/check-self
//        -> { client_ip, banned, decisions: [...] }
//   POST /api/security/decisions/unban-ip
//        body: { ip }   -> { unbanned: N, ip }
//   POST /api/security/whitelist
//        body: { scope, value, reason } -> 201 + { ... }
//
// All require the same authenticated session as the rest of /api/*;
// no route-level guard added here -- the chi router applies the
// session middleware to the whole /api subtree.
//
// The full security panel (decisions list, scenarios, country
// blocking, audit log, dashboard widget) lands in v1.3.20+. The
// slice here is just enough to make the self-block banner work.

// CheckSelfResponse is the body of GET /api/security/check-self.
//
// v1.3.23 expanded shape (multi-IP detection): the banner now
// enumerates every IP the operator's session(s) might be tied to
// and probes LAPI for each. ClientIP / Banned / Decisions are
// kept populated for backwards-compat with v1.3.19/v1.3.22
// banners; new fields support the v2 banner.
type CheckSelfResponse struct {
	// v1.3.19 fields (kept for backwards-compat). ClientIP is
	// the request's resolved IP; Banned + Decisions reflect
	// matches against THAT IP only.
	ClientIP  string              `json:"client_ip"`
	Banned    bool                `json:"banned"`
	Decisions []crowdsec.Decision `json:"decisions"`

	// v1.3.23 multi-IP fields. The banner v2 uses these.
	CurrentSessionIP   string                       `json:"current_session_ip"`
	PublicIPSelf       string                       `json:"public_ip_self,omitempty"`
	ActiveSessionIPs   []string                     `json:"active_session_ips"`
	AnyBanned          bool                         `json:"any_banned"`
	BannedCount        int                          `json:"banned_count"`
	BannedIPs          []BannedIPDetail             `json:"banned_ips"`
}

// BannedIPDetail is one entry in CheckSelfResponse.BannedIPs --
// a specific IP among the caller's active set that has at least
// one matching LAPI decision. Reason is the first matching
// decision's scenario; ExpiresIn is the soonest expiry across
// matching decisions.
type BannedIPDetail struct {
	IP        string              `json:"ip"`
	Source    string              `json:"source"` // "current_session" | "public_ip" | "active_session"
	Decisions []crowdsec.Decision `json:"decisions"`
}

// CheckSelf handles GET /api/security/check-self. v1.3.23 now
// enumerates the IP set:
//
//   1. The current request's resolved IP (h.clientIP).
//   2. The panel's detected public IP (publicip.Detector cache).
//   3. The IPs of any other active sessions belonging to the
//      logged-in user (sessions.client_ip from migration 030).
//
// Each unique IP gets one ListDecisionsByIP probe to LAPI. The
// banner renders BannedIPs to give the operator one click per
// banned IP rather than a single ambiguous "you are banned".
//
// All errors degrade to "not banned" -- a transient LAPI hiccup
// should never paint a scary error across every panel page. The
// next 60s poll retries.
func (h *Handlers) CheckSelf(w http.ResponseWriter, r *http.Request) {
	currentIP := h.clientIP(r)
	resp := CheckSelfResponse{
		ClientIP:         currentIP,
		CurrentSessionIP: currentIP,
		Decisions:        []crowdsec.Decision{},
		ActiveSessionIPs: []string{},
		BannedIPs:        []BannedIPDetail{},
	}
	if h.PublicIP != nil {
		resp.PublicIPSelf = h.PublicIP.Get()
	}

	// Build the unique IP set with source tags, current-session
	// taking precedence so the banner can label it correctly.
	type ipEntry struct {
		ip     string
		source string
	}
	seen := map[string]string{}
	addIP := func(ip, source string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		if _, exists := seen[ip]; exists {
			return
		}
		seen[ip] = source
	}
	addIP(currentIP, "current_session")
	addIP(resp.PublicIPSelf, "public_ip")

	// Active-session IPs from other browsers / devices the same
	// user logged in from. Pre-v1.3.23 sessions have NULL
	// client_ip and are excluded by ListActiveIPsForUser.
	if u, ok := userFromContext(r.Context()); ok {
		others, err := session.ListActiveIPsForUser(r.Context(), h.DB, u.ID)
		if err == nil {
			for _, ip := range others {
				addIP(ip, "active_session")
			}
		}
	}
	for ip := range seen {
		if ip != currentIP { // current already in CurrentSessionIP
			resp.ActiveSessionIPs = append(resp.ActiveSessionIPs, ip)
		}
	}

	if h.CrowdSec == nil || len(seen) == 0 {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Probe LAPI per unique IP. ListDecisionsByIP is cheap (a
	// per-IP filtered query); per-page poll cost stays bounded
	// at ~3-5 LAPI calls.
	for ip, source := range seen {
		decisions, err := h.CrowdSec.ListDecisionsByIP(r.Context(), ip)
		if err != nil {
			continue
		}
		if len(decisions) == 0 {
			continue
		}
		resp.BannedIPs = append(resp.BannedIPs, BannedIPDetail{
			IP:        ip,
			Source:    source,
			Decisions: decisions,
		})
		// Backwards-compat: v1.3.19 banner reads these top-level.
		// Populate from the current-session IP first if it's
		// banned, otherwise from any banned IP.
		if resp.ClientIP != "" && ip == resp.ClientIP {
			resp.Decisions = decisions
		} else if len(resp.Decisions) == 0 {
			resp.Decisions = decisions
		}
	}
	resp.BannedCount = len(resp.BannedIPs)
	resp.AnyBanned = resp.BannedCount > 0
	resp.Banned = resp.AnyBanned // v1.3.19 field
	writeJSON(w, http.StatusOK, resp)
}

type unbanIPRequest struct {
	IP string `json:"ip"`
}

// UnbanIP handles POST /api/security/decisions/unban-ip. Single
// purpose: drop every active LAPI decision for the given IP. No
// reload needed -- LAPI's DELETE /v1/decisions takes effect for
// the next bouncer poll cycle (~15s default). The bouncer also
// revalidates each request's IP against the live decision set, so
// in practice the unban is effective immediately for the unbanned
// client.
//
// The endpoint accepts an explicit IP rather than implicitly
// reading clientIP(r) so an operator on a different network can
// also unban via the API; the self-block banner just passes the
// resolved client IP it got from check-self.
func (h *Handlers) UnbanIP(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		writeError(w, http.StatusServiceUnavailable, "crowdsec client not wired")
		return
	}
	var req unbanIPRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}
	n, err := h.CrowdSec.DeleteDecision(r.Context(), req.IP)
	if err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "crowdsec machine credentials missing; cannot unban from API")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete decision failed: "+err.Error())
		return
	}
	h.audit(r, "security_unban_ip", "ip", 0, map[string]any{
		"ip":       req.IP,
		"unbanned": n,
	})
	writeJSON(w, http.StatusOK, map[string]any{"unbanned": n, "ip": req.IP})
}

type addWhitelistRequest struct {
	Scope  string `json:"scope"` // "ip" | "range"
	Value  string `json:"value"`
	Reason string `json:"reason,omitempty"`
}

// AddWhitelist handles POST /api/security/whitelist. Persists the
// operator-supplied entry to the security_whitelist DB table, then
// rewrites /data/shared/argos-whitelist-entries.txt for
// setup-appsec.sh to consume on its next run.
//
// Important UX note: the unban (handled by UnbanIP) takes effect
// immediately via LAPI; the whitelist takes effect only after the
// operator re-runs setup-appsec.sh + crowdsec picks it up. The
// banner's success toast surfaces the docker-compose-exec command
// the operator needs to run.
func (h *Handlers) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := security.AddManualWhitelist(r.Context(), h.DB, req.Scope, req.Value, req.Reason); err != nil {
		if errors.Is(err, security.ErrDuplicate) {
			writeError(w, http.StatusConflict, "whitelist entry already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "security_whitelist_add", "whitelist", 0, map[string]any{
		"scope":  req.Scope,
		"value":  req.Value,
		"reason": req.Reason,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"scope":          req.Scope,
		"value":          req.Value,
		"reason":         req.Reason,
		"persisted":      true,
		"reload_needed":  true,
		"reload_command": "docker compose exec crowdsec /setup-appsec.sh",
	})
}
