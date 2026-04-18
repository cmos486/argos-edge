// Package waf builds Coraza directive text and Caddy rate-limit JSON
// snippets from the panel's per-host security config.
package waf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// userRuleIDMin and userRuleIDMax are the CRS-recommended range for
// operator-defined SecRules (100000 - 899999). Anything lower clashes
// with Coraza internals; anything higher with Argos-reserved tx ids.
const (
	userRuleIDMin = 100000
	userRuleIDMax = 899999
)

var secRuleIDPattern = regexp.MustCompile(`\bid:(\d+)\b`)

// AllowedDirectives restricts what custom_rules can emit to the
// directives that are safe to append inside a per-host config. Anything
// else (SecAuditLog, SecRuleEngine, SecDefaultAction, ...) is the
// panel's job and would let the operator clobber panel-level settings.
var allowedDirectivePrefixes = []string{
	"SecRule",
	"SecAction",
	"SecMarker",
}

// ValidationError carries a human-oriented message the API surfaces
// back to the operator on 400.
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string { return e.Msg }

// ValidateSecRule runs syntactic checks on a raw SecRule block. It
// does not load Coraza: a full semantic parse would need the engine
// to be initialised with a config, which is too heavy for a request
// handler. Syntax + id bounds catch the common mistakes.
func ValidateSecRule(raw string) (int, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, &ValidationError{Msg: "secrule is empty"}
	}

	// Accept blocks that span multiple lines: strip comments, join
	// continuations. Coraza follows ModSecurity's \-continuation.
	var joined strings.Builder
	for _, line := range strings.Split(text, "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		joined.WriteString(stripped)
		joined.WriteString(" ")
	}
	flat := strings.TrimSpace(joined.String())
	if flat == "" {
		return 0, &ValidationError{Msg: "secrule has no directive (only comments?)"}
	}

	ok := false
	for _, p := range allowedDirectivePrefixes {
		if strings.HasPrefix(flat, p+" ") || strings.HasPrefix(flat, p+"\t") || flat == p {
			ok = true
			break
		}
	}
	if !ok {
		return 0, &ValidationError{Msg: fmt.Sprintf(
			"directive must be one of %s (got %q)",
			strings.Join(allowedDirectivePrefixes, ", "),
			firstToken(flat))}
	}

	// Must carry a numeric id: field inside the action list.
	m := secRuleIDPattern.FindStringSubmatch(flat)
	if len(m) < 2 {
		return 0, &ValidationError{Msg: `missing "id:<n>" action; every rule needs an id`}
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, &ValidationError{Msg: "id is not an integer"}
	}
	if n < userRuleIDMin || n > userRuleIDMax {
		return 0, &ValidationError{Msg: fmt.Sprintf(
			"id %d is outside the operator range %d-%d", n, userRuleIDMin, userRuleIDMax)}
	}

	// Quote balance sanity: ModSecurity actions live inside "..." or
	// '...' strings. Count quotes as a cheap sanity (not perfect but
	// catches common mistakes like a dangling quote).
	if strings.Count(flat, `"`)%2 != 0 {
		return 0, &ValidationError{Msg: "unbalanced double quotes"}
	}
	if strings.Count(flat, "'")%2 != 0 {
		return 0, &ValidationError{Msg: "unbalanced single quotes"}
	}

	return n, nil
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
