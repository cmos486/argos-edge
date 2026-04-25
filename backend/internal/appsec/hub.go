package appsec

import (
	"context"
	"net/http"
	"time"
)

// ProbeHub is the narrow hubLister the argos-panel uses in production.
// CrowdSec does not expose a LAPI endpoint for "list collections" or
// "count appsec rules" (checked against v1.7.7), so the only live
// signal available is: does the AppSec listener answer at all?
//
// Probe: HTTP GET with the bouncer API key header (same header the
// caddy-side plugin sets at request time). v1.3.4 change: pre-1.3.4
// this probe sent no auth and CrowdSec logged `missing API key`
// every time the Status page polled -- the log spam was the
// intentional price of the "401 proves listener is up" trick. Now
// we send the key and accept ANY HTTP response as "up". Only a
// network-level failure (dial refused, timeout) counts as "down".
// CrowdSec AppSec tends to 500 on an authenticated GET without the
// AppSec-specific request headers (X-Crowdsec-Appsec-Ip etc); that
// is still proof of life for liveness-probe purposes.
//
// When the probe succeeds we report the canonical three-collection
// list argos ships via setup-appsec.sh along with the static rule
// count that the shipped configs resolve to (188 at feature launch).
// A static count is more honest than parsing crowdsec stdout logs
// or maintaining a sidecar IPC -- if the operator installs extra
// collections by hand the panel will just keep showing the shipped
// number until we add a refresh path.
type ProbeHub struct {
	URL        string // e.g. http://crowdsec:7423 (any listener works)
	HTTPClient *http.Client
	RuleCount  int // see comment above -- static baseline
}

// NewProbeHub wires a probe against the argos-appsec-detect listener
// by default. The block listener would work equally well.
func NewProbeHub(url string, ruleCount int) *ProbeHub {
	return &ProbeHub{
		URL:        url,
		RuleCount:  ruleCount,
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	}
}

// CollectionsInstalled implements hubLister. Returns the canonical
// set when the AppSec listener is reachable; an empty slice and the
// original error otherwise. The int result is rules count.
func (p *ProbeHub) CollectionsInstalled(ctx context.Context) ([]string, int, error) {
	if p == nil || p.URL == "" || p.HTTPClient == nil {
		return nil, 0, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	if key := bouncerAPIKey(); key != "" {
		req.Header.Set("X-Crowdsec-Appsec-Api-Key", key)
	}
	// v1.3.8: same synthetic AppSec envelope as healthcheck.go --
	// without these four headers CrowdSec logs a `missing 'X-...-Ip'
	// header` error per probe. The values are deliberately benign so
	// no rule can match.
	//
	// v1.3.9: forward a User-Agent header too, otherwise the
	// `crowdsecurity/experimental-no-user-agent` rule classifies the
	// probe as an attack the moment detect-mode SendAlert() is
	// wired up.
	req.Header.Set("X-Crowdsec-Appsec-Ip", "127.0.0.1")
	req.Header.Set("X-Crowdsec-Appsec-Uri", "/.well-known/argos-appsec-probe")
	req.Header.Set("X-Crowdsec-Appsec-Verb", "GET")
	req.Header.Set("X-Crowdsec-Appsec-Host", "argos-panel.local")
	req.Header.Set("X-Crowdsec-Appsec-User-Agent", "argos-panel/probe")
	req.Header.Set("User-Agent", "argos-panel/probe")
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		// Dial / timeout / DNS -- actual connectivity failure.
		return nil, 0, err
	}
	defer resp.Body.Close()
	// Any HTTP status = listener answered. CrowdSec's own reply
	// verb-verdict (200 / 401 / 403 / 405 / 500) is secondary for
	// a liveness probe. The 404 case is treated as "up but
	// misconfigured"; we still report zero collections so the UI
	// renders the "setup-appsec.sh not run" state.
	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, nil
	}
	return CanonicalAppSecCollections(), p.RuleCount, nil
}
