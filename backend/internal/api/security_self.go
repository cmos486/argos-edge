package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/security"
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
// `banned` is true iff at least one active decision matches the
// caller's resolved client IP. `decisions` carries the full
// matching set so the UI banner can render reason + expiration.
type CheckSelfResponse struct {
	ClientIP  string              `json:"client_ip"`
	Banned    bool                `json:"banned"`
	Decisions []crowdsec.Decision `json:"decisions"`
}

// CheckSelf handles GET /api/security/check-self. The self-block
// banner mounts on every panel page and polls this endpoint every
// 60s, so cost matters: we hit the LAPI client's cached
// ListDecisions (30s TTL) and filter client-side on IP equality.
func (h *Handlers) CheckSelf(w http.ResponseWriter, r *http.Request) {
	resp := CheckSelfResponse{
		ClientIP:  h.clientIP(r),
		Decisions: []crowdsec.Decision{},
	}
	if h.CrowdSec == nil || resp.ClientIP == "" {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// Use the IP-filtered LAPI call so a stack with a large CAPI
	// blocklist (50k+ decisions) doesn't drown a per-page poll.
	// LAPI returns just the active decisions for this IP, never
	// more than a handful.
	matches, err := h.CrowdSec.ListDecisionsByIP(r.Context(), resp.ClientIP)
	if err != nil {
		// Don't 500 the banner -- a transient LAPI hiccup should
		// not paint a scary error across every panel page. Fall
		// back to "not banned" so the operator can keep working;
		// the next poll will retry.
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.Decisions = matches
	resp.Banned = len(resp.Decisions) > 0
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
