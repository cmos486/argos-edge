// Package caddy is a thin client for the Caddy Admin API.
//
// Phase 0 only needs read access: probe /config/ to confirm Caddy is alive
// and return a minimal status. Later phases will add writers (/load,
// /config/apps/http/servers/...).
package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a single Caddy instance via its Admin API. The base URL
// must point at the admin listener, e.g. http://caddy:2019.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a Client with sane defaults. baseURL should not include
// a trailing slash but both forms are tolerated.
func NewClient(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// Status is the panel-facing summary of Caddy's admin endpoint.
type Status struct {
	OK      bool   `json:"ok"`
	Address string `json:"address"`
	Error   string `json:"error,omitempty"`
	HasHTTP bool   `json:"has_http"`
}

// Status probes GET /config/ and reports whether Caddy answered with a valid
// JSON document. A nil config (fresh Caddy with no apps loaded yet) still
// counts as OK: the admin API is alive, just empty.
func (c *Client) Status(ctx context.Context) Status {
	s := Status{Address: c.base}
	cfg, err := c.Config(ctx)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	s.OK = true
	if apps, ok := cfg["apps"].(map[string]any); ok {
		_, s.HasHTTP = apps["http"]
	}
	return s
}

// Config returns the full configuration document from GET /config/.
// Returns an empty map when Caddy has no config loaded yet.
func (c *Client) Config(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/config/", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /config/: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Upstream is one entry from Caddy's reverse_proxy upstreams admin
// endpoint. The address is host:port; num_requests and fails are the
// live counters Caddy maintains per upstream pool entry.
type Upstream struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// Upstreams returns every upstream Caddy currently knows about, across
// all reverse_proxy handlers. Returns an empty slice (not nil) when
// Caddy has no handlers wired yet.
func (c *Client) Upstreams(ctx context.Context) ([]Upstream, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/reverse_proxy/upstreams", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /reverse_proxy/upstreams: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return []Upstream{}, nil
	}
	var out []Upstream
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode upstreams: %w", err)
	}
	if out == nil {
		out = []Upstream{}
	}
	return out, nil
}
