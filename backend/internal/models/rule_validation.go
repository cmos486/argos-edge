package models

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// errUnknownActionType is returned by NewAction when the value does not
// match any known action struct; also used by Rule.Validate if the
// envelope's Type field does not map to a known kind.
var errUnknownActionType = errors.New("unknown action type")

var validMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"DELETE":  {},
	"PATCH":   {},
	"HEAD":    {},
	"OPTIONS": {},
}

var validRedirectCodes = map[int]struct{}{
	301: {}, 302: {}, 307: {}, 308: {},
}

// TargetGroupExistsFn is a capability the caller injects so the
// validator can confirm a forward action's target_group_id resolves to
// a real row without dragging the db package into models.
type TargetGroupExistsFn func(id int64) (bool, error)

// Validate runs every phase-3 check against the rule: priority bounds,
// at least one matcher, per-matcher validation, per-action validation.
// When existsFn is non-nil the forward-action target group is also
// checked for existence; pass nil to skip that (e.g. in unit tests).
func (r *Rule) Validate(existsFn TargetGroupExistsFn) error {
	if r.Priority < 1 || r.Priority > 50000 {
		return fmt.Errorf("priority must be between 1 and 50000")
	}
	if len(r.Matchers) == 0 {
		return fmt.Errorf("at least one matcher is required")
	}
	for i, m := range r.Matchers {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("matcher %d (%s): %w", i, m.Type, err)
		}
	}
	if r.Action.Type == "" {
		return fmt.Errorf("action.type is required")
	}
	if err := r.Action.Validate(existsFn); err != nil {
		return fmt.Errorf("action (%s): %w", r.Action.Type, err)
	}
	return nil
}

// --- matcher validators ---

func (m MatcherEnv) Validate() error {
	switch m.Type {
	case MatcherPath:
		c, err := m.AsPath()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if len(c.Patterns) == 0 {
			return fmt.Errorf("at least one pattern required")
		}
		for i, p := range c.Patterns {
			if !strings.HasPrefix(p, "/") {
				return fmt.Errorf("pattern[%d] %q must start with /", i, p)
			}
		}
	case MatcherPathExact:
		c, err := m.AsPathExact()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if len(c.Values) == 0 {
			return fmt.Errorf("at least one value required")
		}
		for i, v := range c.Values {
			if !strings.HasPrefix(v, "/") {
				return fmt.Errorf("value[%d] %q must start with /", i, v)
			}
			if strings.ContainsAny(v, "*?") {
				return fmt.Errorf("value[%d] %q contains glob char; use path matcher for wildcards", i, v)
			}
		}
	case MatcherMethod:
		c, err := m.AsMethod()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if len(c.Methods) == 0 {
			return fmt.Errorf("at least one method required")
		}
		for _, meth := range c.Methods {
			if _, ok := validMethods[strings.ToUpper(meth)]; !ok {
				return fmt.Errorf("method %q not allowed; use GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS", meth)
			}
		}
	case MatcherHeader:
		c, err := m.AsHeader()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("header name required")
		}
		switch c.Mode {
		case HeaderModeExact, "":
		case HeaderModeRegex:
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("regex invalid: %w", err)
			}
		default:
			return fmt.Errorf("mode must be exact or regex")
		}
	case MatcherQuery:
		c, err := m.AsQuery()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("query param name required")
		}
	case MatcherRemoteIP:
		c, err := m.AsRemoteIP()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if len(c.Ranges) == 0 {
			return fmt.Errorf("at least one ip or cidr required")
		}
		for i, r := range c.Ranges {
			if _, _, err := net.ParseCIDR(r); err != nil {
				if ip := net.ParseIP(r); ip == nil {
					return fmt.Errorf("ranges[%d] %q is neither IP nor CIDR", i, r)
				}
			}
		}
	case MatcherHostHeader:
		c, err := m.AsHostHeader()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if len(c.Values) == 0 {
			return fmt.Errorf("at least one host required")
		}
	default:
		return fmt.Errorf("unknown matcher type %q", m.Type)
	}
	return nil
}

// --- action validators ---

func (a ActionEnv) Validate(existsFn TargetGroupExistsFn) error {
	switch a.Type {
	case ActionForward:
		f, err := a.AsForward()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if f.TargetGroupID <= 0 {
			return fmt.Errorf("target_group_id required")
		}
		if existsFn != nil {
			ok, err := existsFn(f.TargetGroupID)
			if err != nil {
				return fmt.Errorf("check target_group_id: %w", err)
			}
			if !ok {
				return fmt.Errorf("target_group_id %d does not exist", f.TargetGroupID)
			}
		}
	case ActionRedirect:
		r, err := a.AsRedirect()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if _, ok := validRedirectCodes[r.StatusCode]; !ok {
			return fmt.Errorf("status_code %d not in 301/302/307/308", r.StatusCode)
		}
		if strings.TrimSpace(r.Target) == "" {
			return fmt.Errorf("target required")
		}
	case ActionFixedResponse:
		r, err := a.AsFixedResponse()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if r.StatusCode < 100 || r.StatusCode > 599 {
			return fmt.Errorf("status_code %d out of 100-599", r.StatusCode)
		}
	case ActionBlock:
		// nothing to validate.
	case ActionRewrite:
		r, err := a.AsRewrite()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if strings.TrimSpace(r.Path) == "" &&
			strings.TrimSpace(r.StripPrefix) == "" &&
			strings.TrimSpace(r.Query) == "" {
			return fmt.Errorf("at least one of path, strip_prefix or query must be set")
		}
		if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("path %q must start with /", r.Path)
		}
		if r.StripPrefix != "" && !strings.HasPrefix(r.StripPrefix, "/") {
			return fmt.Errorf("strip_prefix %q must start with /", r.StripPrefix)
		}
	default:
		return fmt.Errorf("unknown action type %q", a.Type)
	}
	return nil
}
