package models

import (
	"encoding/json"
	"time"
)

// ActionType enumerates rule actions. Stored in the action_type column
// so the reconciler can dispatch without unmarshalling the config.
type ActionType string

const (
	ActionForward       ActionType = "forward"
	ActionRedirect      ActionType = "redirect"
	ActionFixedResponse ActionType = "fixed_response"
	ActionBlock         ActionType = "block"
	ActionRewrite       ActionType = "rewrite"
)

// MatcherType enumerates supported matchers. Each one comes with its
// own config struct below.
type MatcherType string

const (
	MatcherPath       MatcherType = "path"
	MatcherPathExact  MatcherType = "path_exact"
	MatcherMethod     MatcherType = "method"
	MatcherHeader     MatcherType = "header"
	MatcherQuery      MatcherType = "query"
	MatcherRemoteIP   MatcherType = "remote_ip"
	MatcherHostHeader MatcherType = "host_header"
)

// Rule is the typed in-memory shape. action_config and matchers_config
// columns are stored as JSON strings in SQLite; the repository decodes
// them into ActionEnv / []MatcherEnv, and the caddycfg layer further
// unpacks them into concrete config structs per dispatch arm.
type Rule struct {
	ID        int64        `json:"id"`
	HostID    int64        `json:"host_id"`
	Priority  int          `json:"priority"`
	Name      string       `json:"name"`
	Enabled   bool         `json:"enabled"`
	Action    ActionEnv    `json:"action"`
	Matchers  []MatcherEnv `json:"matchers"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// ActionEnv is the tagged envelope used on the wire. Config holds the
// JSON bytes of the concrete action struct; use As<Kind>() to decode.
type ActionEnv struct {
	Type   ActionType      `json:"type"`
	Config json.RawMessage `json:"config"`
}

// MatcherEnv is the tagged envelope for matchers.
type MatcherEnv struct {
	Type   MatcherType     `json:"type"`
	Config json.RawMessage `json:"config"`
}

// --- action configs ---

type ForwardAction struct {
	TargetGroupID int64 `json:"target_group_id"`
}

// RedirectAction supports Caddy placeholders in Target:
// e.g. "https://{http.request.host}/new{http.request.uri.path}".
type RedirectAction struct {
	StatusCode int    `json:"status_code"`
	Target     string `json:"target"`
	StripQuery bool   `json:"strip_query"`
}

type FixedResponseAction struct {
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	ContentType string `json:"content_type"`
}

type BlockAction struct{}

// RewriteAction mutates the request before it reaches the default TG.
// At least one field must be populated. Path and Query may contain
// Caddy placeholders.
type RewriteAction struct {
	Path        string `json:"path,omitempty"`
	StripPrefix string `json:"strip_prefix,omitempty"`
	Query       string `json:"query,omitempty"`
}

// --- matcher configs ---

type PathMatcherConfig struct {
	Patterns []string `json:"patterns"`
}

type PathExactMatcherConfig struct {
	Values []string `json:"values"`
}

type MethodMatcherConfig struct {
	Methods []string `json:"methods"`
}

// HeaderMode is either "exact" or "regex".
type HeaderMode string

const (
	HeaderModeExact HeaderMode = "exact"
	HeaderModeRegex HeaderMode = "regex"
)

type HeaderMatcherConfig struct {
	Name  string     `json:"name"`
	Value string     `json:"value"`
	Mode  HeaderMode `json:"mode"`
}

type QueryMatcherConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RemoteIPMatcherConfig struct {
	Ranges []string `json:"ranges"`
	Negate bool     `json:"negate"`
}

type HostHeaderMatcherConfig struct {
	Values []string `json:"values"`
}

// --- action decoders ---

// AsForward extracts the concrete ForwardAction config.
func (a ActionEnv) AsForward() (ForwardAction, error) {
	var f ForwardAction
	return f, json.Unmarshal(a.Config, &f)
}

func (a ActionEnv) AsRedirect() (RedirectAction, error) {
	var r RedirectAction
	return r, json.Unmarshal(a.Config, &r)
}

func (a ActionEnv) AsFixedResponse() (FixedResponseAction, error) {
	var r FixedResponseAction
	return r, json.Unmarshal(a.Config, &r)
}

func (a ActionEnv) AsRewrite() (RewriteAction, error) {
	var r RewriteAction
	return r, json.Unmarshal(a.Config, &r)
}

// --- matcher decoders ---

func (m MatcherEnv) AsPath() (PathMatcherConfig, error) {
	var c PathMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsPathExact() (PathExactMatcherConfig, error) {
	var c PathExactMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsMethod() (MethodMatcherConfig, error) {
	var c MethodMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsHeader() (HeaderMatcherConfig, error) {
	var c HeaderMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsQuery() (QueryMatcherConfig, error) {
	var c QueryMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsRemoteIP() (RemoteIPMatcherConfig, error) {
	var c RemoteIPMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}
func (m MatcherEnv) AsHostHeader() (HostHeaderMatcherConfig, error) {
	var c HostHeaderMatcherConfig
	return c, json.Unmarshal(m.Config, &c)
}

// --- constructors ---

// NewAction packages a concrete action struct into the wire envelope.
// Callers pass the known concrete type; the kind is inferred from its
// Go type so the API layer does not have to repeat the string.
func NewAction(v any) (ActionEnv, error) {
	var kind ActionType
	switch v.(type) {
	case ForwardAction:
		kind = ActionForward
	case RedirectAction:
		kind = ActionRedirect
	case FixedResponseAction:
		kind = ActionFixedResponse
	case BlockAction:
		kind = ActionBlock
	case RewriteAction:
		kind = ActionRewrite
	default:
		return ActionEnv{}, errUnknownActionType
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ActionEnv{}, err
	}
	return ActionEnv{Type: kind, Config: b}, nil
}

func NewMatcher(t MatcherType, cfg any) (MatcherEnv, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return MatcherEnv{}, err
	}
	return MatcherEnv{Type: t, Config: b}, nil
}
