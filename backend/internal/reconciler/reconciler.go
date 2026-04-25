// Package reconciler pushes the panel's desired Caddy config to the Admin
// API's /load endpoint. Every host mutation calls Apply; startup calls
// ApplyFromDBWithBackoff so a cold caddy container is tolerated.
package reconciler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/caddycfg"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/security"
)

// Reconciler talks to Caddy's Admin API.
type Reconciler struct {
	db        *sql.DB
	adminBase string
	client    *http.Client
	// cipher decrypts the per-provider credentials blobs on every
	// reconcile. Nil-safe: v1.2 call sites that have not migrated
	// yet emit the legacy env-var placeholder instead.
	cipher *crypto.Cipher
}

// New returns a Reconciler wired to the given DB handle and Caddy admin
// base URL, e.g. http://caddy:2019. The cipher is used to decrypt DNS
// provider credentials; passing nil disables the Option 2 inline path
// and forces a fall-back to the legacy {env.CLOUDFLARE_API_TOKEN}
// placeholder for cloudflare hosts.
func New(d *sql.DB, adminBase string, cipher *crypto.Cipher) *Reconciler {
	return &Reconciler{
		db:        d,
		adminBase: adminBase,
		client:    &http.Client{Timeout: 10 * time.Second},
		cipher:    cipher,
	}
}

// ApplyFromDB reads the current enabled host set, every host's enabled
// rules, every referenced target group (both default and rule-
// referenced) and every per-host security bundle, then pushes the
// derived config to Caddy.
func (r *Reconciler) ApplyFromDB(ctx context.Context) error {
	hosts, err := db.ListEnabledHosts(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list enabled hosts: %w", err)
	}

	rulesByHost := make(map[int64][]models.Rule, len(hosts))
	securityByHost := make(map[int64]models.HostSecurityBundle, len(hosts))
	tgIDs := map[int64]struct{}{}
	for _, h := range hosts {
		tgIDs[h.TargetGroupID] = struct{}{}

		rules, err := db.ListEnabledRulesByHost(ctx, r.db, h.ID)
		if err != nil {
			return fmt.Errorf("list rules for host %s: %w", h.Domain, err)
		}
		rulesByHost[h.ID] = rules
		for _, rule := range rules {
			if rule.Action.Type == models.ActionForward {
				f, err := rule.Action.AsForward()
				if err == nil && f.TargetGroupID > 0 {
					tgIDs[f.TargetGroupID] = struct{}{}
				}
			}
		}

		bundle, err := db.LoadHostSecurityBundle(ctx, r.db, h.ID)
		if err != nil {
			return fmt.Errorf("load security bundle for host %s: %w", h.Domain, err)
		}
		securityByHost[h.ID] = bundle
	}

	groups := make(map[int64]*models.TargetGroup, len(tgIDs))
	for id := range tgIDs {
		tg, err := db.GetTargetGroup(ctx, r.db, id)
		if err != nil {
			return fmt.Errorf("hydrate target group %d: %w", id, err)
		}
		groups[id] = &tg
	}
	return r.Apply(ctx, hosts, rulesByHost, groups, securityByHost)
}

// Apply pushes the config derived from the explicit host set + rules +
// hydrated target groups + security bundles. Mutation handlers use
// this variant with the just-written state.
func (r *Reconciler) Apply(
	ctx context.Context,
	hosts []models.Host,
	rulesByHost map[int64][]models.Rule,
	groups map[int64]*models.TargetGroup,
	securityByHost map[int64]models.HostSecurityBundle,
) error {
	cfg, err := caddycfg.HostsToCaddyConfig(hosts, rulesByHost, groups, securityByHost, r.crowdsecOpts(ctx), r.acmeOpts(ctx), r.dnsOpts(ctx))
	if err != nil {
		return fmt.Errorf("build caddy config: %w", err)
	}
	if err := r.load(ctx, cfg); err != nil {
		return err
	}
	// v1.3.19: refresh the panel-managed CrowdSec sentinel files
	// (true_detect_mode hosts, manual whitelist) on every Caddy
	// reconcile. Both writes are best-effort against the shared
	// volume; a missing /data/shared (dev runs outside docker) is
	// a no-op. CrowdSec picks up changes only on the next
	// `setup-appsec.sh` run -- the panel UI tells the operator.
	if err := security.WriteTrueDetectHosts(ctx, r.db); err != nil {
		slog.Warn("write true-detect sentinel failed", "error", err)
	}
	if err := security.WriteWhitelistEntries(ctx, r.db); err != nil {
		slog.Warn("write whitelist sentinel failed", "error", err)
	}
	return nil
}

// dnsOpts loads every enabled dns_providers row, decrypts credentials
// once per reconcile, and hands them to the caddycfg generator for
// inline emission into the /load JSON (Option 2). The legacy env-var
// fallback is set for cloudflare when no DB row is enabled but the
// env var exists -- that covers the window between v1.3 upgrade and
// the operator removing CLOUDFLARE_API_TOKEN from .env.
//
// Cipher-less operation (e.g. tests that construct a Reconciler
// with nil cipher) short-circuits to legacy-only: Providers=nil,
// LegacyCFEnvSet reflects the env var. Hosts pointing at non-
// cloudflare providers then emit a name-only block and fail
// issuance with a clear message.
func (r *Reconciler) dnsOpts(ctx context.Context) caddycfg.DNSOpts {
	out := caddycfg.DNSOpts{
		LegacyCFEnvSet: os.Getenv("CLOUDFLARE_API_TOKEN") != "",
	}
	if r.cipher == nil {
		return out
	}
	providers, err := db.LoadEnabledDNSCredentials(ctx, r.db, r.cipher)
	if err != nil {
		// Partial-load: one decrypt failed but others may have
		// succeeded. Log the error, use whatever the repo could
		// recover. Aborting reconcile would break every other host
		// in the panel for a single misconfigured row.
		slog.Warn("dns provider: partial decrypt failure", "error", err)
	}
	out.Providers = providers
	// If a cloudflare row is enabled in the DB we prefer the DB
	// credentials over the env var; suppress the legacy fallback
	// so the generator does not emit both api_token sources.
	if _, cfInDB := providers["cloudflare"]; cfInDB {
		out.LegacyCFEnvSet = false
	}
	return out
}

// acmeOpts reads the env override + global setting for the ACME CA
// URL on every reconcile. Reading per-reconcile (rather than caching)
// keeps a settings edit taking effect on the very next /load without
// a panel restart; the query cost is one indexed SELECT.
func (r *Reconciler) acmeOpts(ctx context.Context) caddycfg.ACMEOpts {
	return caddycfg.ACMEOpts{
		EnvCAURL:    os.Getenv("ARGOS_ACME_CA_URL"),
		GlobalCAURL: db.GetSettingValue(ctx, r.db, "acme.ca_url", ""),
	}
}

// AppSec endpoints: crowdsec listens on two ports inside argos_net
// with different appsec-configs. The bouncer picks one URL per
// request based on the panel's appsec.mode setting. "disabled"
// emits the empty string so the generator omits appsec_url
// entirely.
const (
	appsecBlockURL  = "http://crowdsec:7422"
	appsecDetectURL = "http://crowdsec:7423"
)

// AppSecURLForMode translates the persisted appsec.mode setting into
// the URL the Caddy bouncer should talk to. Exported so the api
// layer can preview what reconcile will emit before it commits the
// DB flip (keeps the rollback path clean).
func AppSecURLForMode(mode string) string {
	switch mode {
	case "block":
		return appsecBlockURL
	case "detect":
		return appsecDetectURL
	default: // "disabled" or any unexpected value -> off
		return ""
	}
}

// crowdsecOpts decides whether to emit the CrowdSec bouncer app +
// per-host handler. The bouncer runs only when (1) crowdsec.enabled
// setting is true, AND (2) the CROWDSEC_BOUNCER_API_KEY env var is
// set on the caddy container. The panel itself does NOT embed the
// key in the generated JSON; it only probes "is the key configured"
// via crowdsec.bouncer_api_key in settings so the Caddy config and
// the UI stay in sync. AppSec fields piggyback on the same app
// block -- they are inert when appsec.mode is "disabled".
func (r *Reconciler) crowdsecOpts(ctx context.Context) caddycfg.CrowdSecOpts {
	enabled := db.GetSettingValue(ctx, r.db, "crowdsec.enabled", "true") == "true"
	configured := db.GetSettingValue(ctx, r.db, "crowdsec.bouncer_configured", "false") == "true"
	if !enabled || !configured {
		return caddycfg.CrowdSecOpts{}
	}
	appsecMode := db.GetSettingValue(ctx, r.db, "appsec.mode", "detect")
	// appsec.fail_open defaults to "true" in v1.3.2+: a dead AppSec
	// sidecar used to 500 every request on every host. Operators who
	// actively run AppSec with a functioning collection set can flip
	// this to "false" to restore strict enforcement.
	appsecFailOpen := db.GetSettingValue(ctx, r.db, "appsec.fail_open", "true") == "true"
	return caddycfg.CrowdSecOpts{
		Enabled:        true,
		LAPIURL:        db.GetSettingValue(ctx, r.db, "crowdsec.lapi_url", "http://crowdsec:8081"),
		TickerInterval: "15s",
		AppSecURL:      AppSecURLForMode(appsecMode),
		AppSecFailOpen: appsecFailOpen,
	}
}

// ApplyFromDBWithBackoff retries ApplyFromDB up to 30 seconds with
// exponential backoff (500ms, 1s, 2s, 4s, 8s, 8s...). Used at startup
// where caddy may be a few seconds behind the panel.
func (r *Reconciler) ApplyFromDBWithBackoff(ctx context.Context) error {
	delay := 500 * time.Millisecond
	deadline := time.Now().Add(30 * time.Second)

	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := r.ApplyFromDB(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().Add(delay).After(deadline) {
			break
		}
		slog.Warn("reconcile failed, retrying",
			"attempt", attempt, "error", lastErr, "delay", delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > 8*time.Second {
			delay = 8 * time.Second
		}
	}
	return fmt.Errorf("reconcile exhausted 30s backoff: %w", lastErr)
}

// ErrInvalidAppSecMode is returned by SetAppSecMode when the caller
// passes a value other than detect/block/disabled.
var ErrInvalidAppSecMode = errors.New("appsec.mode must be one of: detect, block, disabled")

// ValidAppSecMode reports whether m is one of the three accepted
// runtime modes. Exported so the api layer can validate without
// pulling in the reconciler implementation.
func ValidAppSecMode(m string) bool {
	return m == "detect" || m == "block" || m == "disabled"
}

// SetAppSecMode flips the appsec.mode setting AND pushes a fresh
// Caddy config in one call. On reconcile failure the previous mode
// is restored so the panel's DB and the running Caddy config never
// disagree. Returns the previous mode (for audit diffs) and any
// error. Safe to call with mode == current mode: the reconcile still
// runs so callers can use this to force a re-reconcile after a
// crowdsec restart.
func (r *Reconciler) SetAppSecMode(ctx context.Context, mode string) (prev string, err error) {
	if !ValidAppSecMode(mode) {
		return "", ErrInvalidAppSecMode
	}
	prev = db.GetSettingValue(ctx, r.db, "appsec.mode", "detect")
	if uerr := db.UpsertSetting(ctx, r.db, "appsec.mode", mode); uerr != nil {
		return prev, fmt.Errorf("persist appsec.mode: %w", uerr)
	}
	if rerr := r.ApplyFromDB(ctx); rerr != nil {
		// Reconcile failed -- restore the old value so the next
		// boot + any future reconcile goes back to what Caddy is
		// actually serving. Best-effort: if the rollback itself
		// fails we log and return the original error so the caller
		// learns about the real problem.
		if rb := db.UpsertSetting(ctx, r.db, "appsec.mode", prev); rb != nil {
			slog.Error("appsec.mode rollback failed after reconcile error",
				"reconcile_error", rerr, "rollback_error", rb,
				"attempted", mode, "kept", prev)
		}
		return prev, fmt.Errorf("reconcile after appsec.mode=%s: %w", mode, rerr)
	}
	return prev, nil
}

func (r *Reconciler) load(ctx context.Context, cfg json.RawMessage) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.adminBase+"/load", bytes.NewReader(cfg))
	if err != nil {
		return fmt.Errorf("build /load request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /load: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy /load returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
