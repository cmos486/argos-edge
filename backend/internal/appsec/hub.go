package appsec

import (
	"context"
	"net/http"
	"time"
)

// ProbeHub is the narrow hubLister the argos-panel uses in production.
// CrowdSec does not expose a LAPI endpoint for "list collections" or
// "count appsec rules" (checked against v1.7.7), so the only live
// signal available is: does the AppSec listener answer? An
// unauthenticated GET returns 401 when the listener is running with
// an appsec-config loaded, and errors out (or returns 000) otherwise.
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
// by default. The block listener would work equally well; either
// answering 401 proves AppSec is configured.
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
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	// 401 = listener up, appsec-config loaded, just missing the
	// bouncer API key. Any 2xx/4xx other than 0 is also "up".
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return CanonicalAppSecCollections(), p.RuleCount, nil
	}
	return nil, 0, nil
}
