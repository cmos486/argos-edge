// Package dnsproviders is the catalogue of ACME DNS-01 providers the
// panel knows how to configure on Caddy. Each Provider entry describes:
//
//   - its stable name (matches dns_providers.name in the DB);
//   - the fields Caddy's dns.providers.<name> module expects in the
//     /load JSON (api_token for cloudflare, access_key_id + secret_
//     access_key + optional region for route53, ...);
//   - which of those fields are required (empty is rejected at save
//     time) vs optional (empty means "use the provider default");
//   - the exact module name Caddy uses to resolve the plugin (same
//     string that appears after `dns.providers.` in the compiled
//     module registry).
//
// The catalogue is static Go data, intentionally not stored in the
// DB: adding a provider is a code change + a Dockerfile --with line,
// not a migration. Keeping provider shape here lets the API layer
// validate incoming credential blobs and the caddycfg generator emit
// the right JSON without either of them embedding the provider table.
//
// Sub-phase A (v1.3.0-alpha) ships with cloudflare + route53 only.
// More providers land in later sub-phases; extending the DB CHECK
// on dns_providers.name is a separate migration at that point.
package dnsproviders

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ProviderField describes one credential input the Caddy DNS module
// accepts. Label / Placeholder are UI hints consumed by the Settings
// page in sub-phase B; the backend only enforces Key + Required.
type ProviderField struct {
	// Key is the JSON field name Caddy's dns.providers.<name> module
	// expects inside its config block (e.g. "api_token").
	Key string
	// Label is the human-facing label the Settings form shows.
	Label string
	// Required makes the field mandatory at save time; an empty
	// value triggers a validation error.
	Required bool
	// Placeholder is an example value shown as input placeholder in
	// the UI. Pure hint, not persisted.
	Placeholder string
	// Secret, when true, flags the field for treatment as a password
	// input (masked + __UNCHANGED__ sentinel on round-trip).
	Secret bool
}

// Provider is one entry in the catalogue.
type Provider struct {
	// Name is the stable identifier; matches dns_providers.name and
	// the value stored in hosts.tls_dns_provider.
	Name string
	// DisplayName is the label shown in the Settings page + host
	// dropdown.
	DisplayName string
	// Fields enumerates the credential inputs in display order.
	Fields []ProviderField
	// CaddyModule is the string Caddy uses to load the plugin. It
	// almost always matches Name but is kept separate so the panel
	// can rename a provider in the UI without breaking a running
	// Caddy config.
	CaddyModule string
	// DocsURL points at the provider's token/credentials page so the
	// UI can surface a "how do I get this?" link.
	DocsURL string
}

// catalog is the authoritative list. Keep the order stable: the
// Settings page renders cards in this sequence.
var catalog = []Provider{
	{
		Name:        "cloudflare",
		DisplayName: "Cloudflare",
		Fields: []ProviderField{
			{
				Key:         "api_token",
				Label:       "API Token",
				Required:    true,
				Placeholder: "Zone:DNS:Edit scoped token",
				Secret:      true,
			},
		},
		CaddyModule: "cloudflare",
		DocsURL:     "https://dash.cloudflare.com/profile/api-tokens",
	},
	{
		Name:        "route53",
		DisplayName: "AWS Route 53",
		Fields: []ProviderField{
			{
				Key:         "access_key_id",
				Label:       "AWS Access Key ID",
				Required:    true,
				Placeholder: "AKIAIOSFODNN7EXAMPLE",
			},
			{
				Key:         "secret_access_key",
				Label:       "AWS Secret Access Key",
				Required:    true,
				Placeholder: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				Secret:      true,
			},
			{
				Key:         "region",
				Label:       "AWS Region",
				Required:    false,
				Placeholder: "us-east-1 (default)",
			},
		},
		CaddyModule: "route53",
		DocsURL:     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
	},
}

// ErrUnknownProvider is returned when a caller asks for a name that
// the catalogue does not know about. Exported so handlers can
// errors.Is() and return 404.
type ErrUnknownProvider struct{ Name string }

func (e ErrUnknownProvider) Error() string {
	return fmt.Sprintf("unknown DNS provider: %q", e.Name)
}

// List returns the catalogue in stable display order. Callers must
// not mutate the returned slice (fields are shared structs).
func List() []Provider {
	out := make([]Provider, len(catalog))
	copy(out, catalog)
	return out
}

// Get returns the catalogue entry for name, or ErrUnknownProvider
// when the name is not present.
func Get(name string) (Provider, error) {
	for i := range catalog {
		if catalog[i].Name == name {
			return catalog[i], nil
		}
	}
	return Provider{}, ErrUnknownProvider{Name: name}
}

// KnownNames returns every provider name in the catalogue, sorted.
// Used by the API to surface the supported set and by tests to
// iterate the catalogue deterministically.
func KnownNames() []string {
	names := make([]string, 0, len(catalog))
	for _, p := range catalog {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

// ValidateCredentials checks that every required field has a
// non-empty value and that no unknown fields sneak through. It does
// NOT reach out to the DNS provider's API -- that would be a
// Test-Connection button, not save-time validation. Empty map is a
// hard error: "enabled provider must have credentials".
func ValidateCredentials(name string, creds map[string]string) error {
	p, err := Get(name)
	if err != nil {
		return err
	}
	known := make(map[string]ProviderField, len(p.Fields))
	for _, f := range p.Fields {
		known[f.Key] = f
	}
	// Required-field presence.
	for _, f := range p.Fields {
		if !f.Required {
			continue
		}
		v, ok := creds[f.Key]
		if !ok || strings.TrimSpace(v) == "" {
			return fmt.Errorf("DNS provider %s: field %q is required", name, f.Key)
		}
	}
	// Unknown fields -- catch typos early.
	for k := range creds {
		if _, ok := known[k]; !ok {
			return fmt.Errorf("DNS provider %s: unknown field %q", name, k)
		}
	}
	return nil
}

// FilterKnownFields returns a new map containing only the credential
// keys the provider catalogue lists, dropping anything else. Empty
// string values are preserved (callers may save "region":"" to
// explicitly clear a previously-set optional). The result is the
// shape serialised into the encrypted blob on save.
func FilterKnownFields(name string, creds map[string]string) map[string]string {
	p, err := Get(name)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(p.Fields))
	for _, f := range p.Fields {
		if v, ok := creds[f.Key]; ok {
			out[f.Key] = v
		}
	}
	return out
}

// EncodeCredentials marshals a credentials map to JSON in a stable
// key order. Centralised here so the DB repo and any future caller
// agree on serialisation without either of them thinking about
// map-iteration order.
func EncodeCredentials(creds map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(creds))
	for k := range creds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make([][2]string, 0, len(creds))
	for _, k := range keys {
		ordered = append(ordered, [2]string{k, creds[k]})
	}
	// json.Marshal on map[string]string is already sorted in Go's
	// stdlib, but encoding via the explicit slice keeps the contract
	// explicit for readers + stable if the stdlib behaviour changed.
	m := make(map[string]string, len(creds))
	for _, kv := range ordered {
		m[kv[0]] = kv[1]
	}
	return json.Marshal(m)
}

// DecodeCredentials is the counterpart to EncodeCredentials. Empty
// input returns an empty (non-nil) map so callers can range over it
// unconditionally.
func DecodeCredentials(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}
