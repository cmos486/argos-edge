// Package publicip detects the panel's outbound public IP via a
// pluggable detection URL (defaults to api.ipify.org). The cached
// value powers SelfBlockBanner v2 multi-IP detection: an operator
// hitting the panel via LAN never sees their public WAN IP from
// the request itself, but the panel's own outbound calls resolve
// through the same NAT.
//
// Failure modes are all graceful: the panel is fully functional
// without a public IP detection. Empty string / unset is the
// "unknown" state; callers degrade.
package publicip

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// SettingKey is the panel setting that caches the last detected
// public IP. The poller writes here so the value survives panel
// restarts; a fresh boot starts with the previous value cached
// and refreshes via the next poll tick.
const SettingKey = "panel.public_ip_self"

// SettingDetectURL overrides the default ipify endpoint. Empty /
// missing falls back to DefaultDetectURL. Operators set this to
// "" via the settings API to disable detection (or set the env
// var ARGOS_PUBLIC_IP_DISABLE=1 at boot).
const SettingDetectURL = "panel.public_ip_detect_url"

// DefaultDetectURL is api.ipify.org's JSON endpoint. Free, no
// API key, returns {"ip":"X.X.X.X"}. Replaceable per-deploy.
const DefaultDetectURL = "https://api.ipify.org/?format=json"

// DefaultInterval is how often the poller refreshes. Longer
// intervals reduce dependency on the upstream; shorter intervals
// catch dynamic-IP changes faster.
const DefaultInterval = 1 * time.Hour

// FailureBackoff is the retry delay after a poll fails. Keeps
// the panel polite against the upstream during outages.
const FailureBackoff = 5 * time.Minute

// Detector caches the last detected public IP behind an atomic
// pointer for cheap concurrent reads. Get returns "" until the
// first successful poll (or until Load reads the previous value
// from settings).
type Detector struct {
	db        *sql.DB
	httpC     *http.Client
	mu        sync.Mutex
	cached    atomic.Pointer[string]
	stopped   atomic.Bool
	lastError atomic.Pointer[string]
	lastAt    atomic.Int64
}

// New returns a detector bound to db. The http client is given a
// short timeout so a hung ipify upstream cannot stall the panel
// shutdown path; the worker still respects ctx.Done().
func New(d *sql.DB) *Detector {
	return &Detector{
		db:    d,
		httpC: &http.Client{Timeout: 10 * time.Second},
	}
}

// LoadCached reads the previously-detected IP from settings into
// the in-memory cache. Call once at boot before Start so /api
// readers see the previous value while the next poll runs.
func (d *Detector) LoadCached(ctx context.Context) {
	v := db.GetSettingValue(ctx, d.db, SettingKey, "")
	if v != "" {
		s := v
		d.cached.Store(&s)
	}
}

// Get returns the cached public IP. Empty when never resolved.
func (d *Detector) Get() string {
	if p := d.cached.Load(); p != nil {
		return *p
	}
	return ""
}

// Status is the snapshot exposed to the api package for the
// /api/security/public-ip-self endpoint and for debugging.
type Status struct {
	IP        string    `json:"ip"`
	LastAt    time.Time `json:"last_at"`
	LastError string    `json:"last_error,omitempty"`
	DetectURL string    `json:"detect_url"`
	Disabled  bool      `json:"disabled"`
}

// Status returns a thread-safe snapshot.
func (d *Detector) Status(ctx context.Context) Status {
	st := Status{
		IP:        d.Get(),
		DetectURL: d.detectURL(ctx),
	}
	if st.DetectURL == "" {
		st.Disabled = true
	}
	if ts := d.lastAt.Load(); ts > 0 {
		st.LastAt = time.Unix(0, ts).UTC()
	}
	if e := d.lastError.Load(); e != nil {
		st.LastError = *e
	}
	return st
}

// Start kicks off the background poll loop. Returns immediately;
// the goroutine runs until ctx is cancelled. interval=0 falls
// back to DefaultInterval.
//
// Disabled paths:
//   - panel.public_ip_detect_url == "" in settings -> no polling
//   - ARGOS_PUBLIC_IP_DISABLE=1 env var -> Start short-circuits
//
// Both paths leave Get() returning the previously cached value
// (if any) and Status.Disabled=true.
func (d *Detector) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	go func() {
		// First tick: poll immediately so the cache warms within
		// seconds of boot rather than after a full interval.
		_ = d.refreshOnce(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				d.stopped.Store(true)
				return
			case <-t.C:
				_ = d.refreshOnce(ctx)
			}
		}
	}()
}

// refreshOnce performs a single detection attempt + cache update.
// Errors are recorded into lastError but never propagated as a
// fatal -- the poller keeps trying.
func (d *Detector) refreshOnce(ctx context.Context) error {
	url := d.detectURL(ctx)
	if url == "" {
		// Detection disabled by settings; nothing to do.
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	ip, err := d.detect(ctx, url)
	now := time.Now().UTC()
	d.lastAt.Store(now.UnixNano())
	if err != nil {
		msg := err.Error()
		d.lastError.Store(&msg)
		slog.Debug("publicip: detect failed", "url", url, "error", err)
		return err
	}
	clean := ""
	d.lastError.Store(&clean)
	d.cached.Store(&ip)
	if err := db.UpsertSetting(ctx, d.db, SettingKey, ip); err != nil {
		slog.Warn("publicip: persist failed", "error", err)
	}
	return nil
}

func (d *Detector) detectURL(ctx context.Context) string {
	v := db.GetSettingValue(ctx, d.db, SettingDetectURL, DefaultDetectURL)
	return strings.TrimSpace(v)
}

// detect performs one HTTP request to the detection URL and
// extracts an IP from the response. Supports both the JSON shape
// {"ip":"X"} and the plaintext shape (icanhazip.com style) so
// operators who swap the URL don't need a custom parser.
func (d *Detector) detect(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "argos-edge/publicip")
	resp, err := d.httpC.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("upstream %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(body))
	// JSON shape first.
	var j struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(trimmed), &j); err == nil && j.IP != "" {
		return j.IP, nil
	}
	// Plaintext fallback. Strip whitespace; reject anything that
	// doesn't look like an IP literal so a misconfigured URL
	// returning HTML doesn't poison the cache.
	if looksLikeIP(trimmed) {
		return trimmed, nil
	}
	return "", fmt.Errorf("could not parse response (%d bytes)", len(trimmed))
}

func looksLikeIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	dots := 0
	colons := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case r == '.':
			dots++
		case r == ':':
			colons++
		default:
			return false
		}
	}
	return (dots == 3 && colons == 0) || colons >= 2
}
