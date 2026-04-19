package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/session"
)

// forwardAuthCacheTTL is how long a validated session is trusted
// before we re-lookup in SQLite. 30s matches the dashboard cache
// cadence and caps the staleness window for a revoked session to
// under 30s -- short enough for a homelab panel, long enough that
// every passing request does not touch the DB.
const forwardAuthCacheTTL = 30 * time.Second

// forwardAuthRecord is what the cache stores per session token.
// Keyed by the opaque cookie value, not user id, because Logout
// invalidates tokens directly.
type forwardAuthRecord struct {
	user      session.User
	validAt   time.Time
	expiresAt time.Time
	// email + display + provider pulled once from the users row to
	// avoid a second query per cached request. Static per session.
	email       string
	displayName string
	provider    string
}

// ForwardAuthCache is the in-process LRU-ish cache for /auth/forward.
// Entries live at most forwardAuthCacheTTL; stale entries are evicted
// lazily on read + swept on a timer.
type ForwardAuthCache struct {
	mu    sync.Mutex
	items map[string]forwardAuthRecord
}

// NewForwardAuthCache returns an empty cache.
func NewForwardAuthCache() *ForwardAuthCache {
	return &ForwardAuthCache{items: make(map[string]forwardAuthRecord)}
}

// StartSweeper runs periodic eviction until ctx is cancelled. Cheap
// map scan every 30s.
func (c *ForwardAuthCache) StartSweeper(ctx context.Context) {
	go func() {
		t := time.NewTicker(forwardAuthCacheTTL)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UTC()
				c.mu.Lock()
				for k, v := range c.items {
					if now.After(v.expiresAt) {
						delete(c.items, k)
					}
				}
				c.mu.Unlock()
			}
		}
	}()
}

// Invalidate drops one token's entry. Called from Logout so a user
// who signs out sees their protected hosts bounce to /login within
// one round trip rather than waiting out the 30s TTL.
func (c *ForwardAuthCache) Invalidate(token string) {
	c.mu.Lock()
	delete(c.items, token)
	c.mu.Unlock()
}

// ForwardAuth GET /api/auth/forward
//
// Caddy hits this per-request for hosts with auth_required=1. The
// caddy-forward-auth directive forwards the original Host / URI /
// Method as X-Forwarded-* headers + the client's cookies. Response
// contract:
//
//   - 200 OK + headers X-Auth-{User,Email,Name,Provider}: caller
//     (Caddy) copies the X-Auth-* headers onto the upstream request
//     so the backend (Huntlo, etc.) knows who's asking.
//   - 302 Found + Location=<panel>/login?rd=<original_url>: session
//     missing or expired. Caddy propagates the 302 to the browser.
//
// Never 401: the spec wants a browser-redirect flow, not a challenge
// the upstream would see as an error response.
func (h *Handlers) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	origURL := reconstructOriginalURL(r)
	// Pull the argos cookie the browser sent. Caddy forwards the
	// full Cookie header, so the standard r.Cookie lookup works.
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		h.forwardRedirectToLogin(w, r, origURL)
		return
	}

	// Cache hit?
	if rec, ok := h.ForwardAuthCache.get(c.Value); ok {
		h.forwardSetAuthHeaders(w, rec)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Miss: do the real lookup, honoring the idle timeout.
	var idleTTL time.Duration
	if h.Timeouts != nil {
		_, idleTTL = h.Timeouts.Get(r.Context())
	} else {
		idleTTL = session.DefaultIdleTTL
	}
	_, u, err := session.Lookup(r.Context(), h.DB, c.Value, idleTTL)
	if err != nil {
		h.forwardRedirectToLogin(w, r, origURL)
		return
	}
	// Touch last_seen_at so an active session on a protected host
	// keeps the idle clock alive for the panel too.
	if s2, _, lerr := session.Lookup(r.Context(), h.DB, c.Value, idleTTL); lerr == nil {
		_, _ = session.Touch(r.Context(), h.DB, s2)
	}

	// Fetch the extra identity columns (email + display_name +
	// external_provider). A miss here is non-fatal -- an older
	// pre-Phase-A row has NULL email; we still allow the request
	// through with the local username header.
	rec := forwardAuthRecord{
		user:      u,
		validAt:   time.Now().UTC(),
		expiresAt: time.Now().UTC().Add(forwardAuthCacheTTL),
		provider:  "local",
	}
	var email, display, extProv string
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(email,''), COALESCE(display_name,''), COALESCE(external_provider,'')
		   FROM users WHERE id=?`, u.ID).Scan(&email, &display, &extProv)
	rec.email = email
	rec.displayName = display
	if extProv != "" {
		rec.provider = extProv
	}

	h.ForwardAuthCache.put(c.Value, rec)
	h.forwardSetAuthHeaders(w, rec)
	w.WriteHeader(http.StatusOK)
}

// reconstructOriginalURL builds the URL the user was trying to hit
// BEFORE Caddy bounced them to us. Caddy sets X-Forwarded-* headers
// on the subrequest to forward_auth; we assemble them here so rd=
// can send the browser back to the exact page after login.
func reconstructOriginalURL(r *http.Request) string {
	scheme := "https"
	if xp := r.Header.Get("X-Forwarded-Proto"); xp != "" {
		scheme = xp
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	if uri == "" || !strings.HasPrefix(uri, "/") {
		uri = "/"
	}
	return scheme + "://" + host + uri
}

// forwardRedirectToLogin emits the 302 a browser needs to end up on
// the panel's /login with the rd= param pointing back at the
// protected host. We use the SCHEMED panel URL (not a bare path)
// because the browser might be on a different host entirely --
// relative paths would not leave the protected host.
//
// Panel URL resolution: PanelDomain (if set at boot) wins; else we
// fall back to Host -- pragmatic but only correct when the panel is
// accessed at the same hostname as the protected host (i.e. never
// in ForwardAuth deployments, so we expect PanelDomain set).
func (h *Handlers) forwardRedirectToLogin(w http.ResponseWriter, r *http.Request, originalURL string) {
	panelBase := "https://" + h.PanelDomain
	if h.PanelDomain == "" {
		// No configured domain (LAN mode). Best we can do is a
		// relative path; the browser stays on whatever host it was
		// and gets a 404 from their backend, but the operator was
		// warned at config time.
		http.Redirect(w, r, "/login?rd="+queryEscape(originalURL), http.StatusFound)
		return
	}
	loginURL := panelBase + "/login?rd=" + queryEscape(originalURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *Handlers) forwardSetAuthHeaders(w http.ResponseWriter, rec forwardAuthRecord) {
	w.Header().Set("X-Auth-User", rec.user.Username)
	if rec.email != "" {
		w.Header().Set("X-Auth-Email", rec.email)
	}
	if rec.displayName != "" {
		w.Header().Set("X-Auth-Name", rec.displayName)
	}
	if rec.provider != "" {
		w.Header().Set("X-Auth-Provider", rec.provider)
	}
}

// --- cache methods ---

func (c *ForwardAuthCache) get(token string) (forwardAuthRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.items[token]
	if !ok {
		return forwardAuthRecord{}, false
	}
	if time.Now().UTC().After(rec.expiresAt) {
		delete(c.items, token)
		return forwardAuthRecord{}, false
	}
	return rec, true
}

func (c *ForwardAuthCache) put(token string, rec forwardAuthRecord) {
	c.mu.Lock()
	c.items[token] = rec
	c.mu.Unlock()
}

// queryEscape is url.QueryEscape with the one tweak we actually
// want here: keep "/" unescaped so the rd= value reads naturally in
// server logs. QueryEscape would turn /dashboard into %2Fdashboard
// which works but is ugly; PathEscape keeps slashes + escapes the
// rest of the reserved characters, which is exactly the semantics a
// URL-in-URL needs.
func queryEscape(s string) string {
	// url.PathEscape leaves + unescaped too; replace it manually
	// because Go's net/http Redirect does not re-decode + as space
	// and the browser will show %2B vs + interchangeably.
	return strings.ReplaceAll(url.PathEscape(s), "+", "%2B")
}
