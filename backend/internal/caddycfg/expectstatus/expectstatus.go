// Package expectstatus parses the operator-friendly expect_status
// patterns the panel accepts ("200", "200,301,302", "200-299",
// "200-204,301") into the representation Caddy's JSON active health
// check can consume.
//
// Caddy's JSON expect_status is a single integer: an exact 3-digit
// code ("200") or a 1-digit class ("2" = 2xx). It cannot express a
// literal set of codes. The mapping is therefore:
//
//   - single code      -> exact int
//   - one class range  -> class digit (full class, no over-acceptance)
//   - subset of class  -> class digit + note (Caddy will also accept
//                          other codes in the same class)
//   - multi-class set  -> 0 + note (the caller drops expect_status so
//                          the active check does not enforce a status)
package expectstatus

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Spec is a normalized, deduplicated set of HTTP status codes.
type Spec struct {
	codes []int
}

// Parse validates raw, expands ranges and dedupes. Returns error on
// empty input, out-of-range codes (must be 100-599), reversed ranges,
// or unparseable tokens.
func Parse(raw string) (Spec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Spec{}, errors.New("expect_status cannot be empty")
	}

	set := map[int]struct{}{}
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return Spec{}, fmt.Errorf("empty token in %q", raw)
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			start, err := parseCode(parts[0])
			if err != nil {
				return Spec{}, fmt.Errorf("range %q: start: %w", token, err)
			}
			end, err := parseCode(parts[1])
			if err != nil {
				return Spec{}, fmt.Errorf("range %q: end: %w", token, err)
			}
			if start > end {
				return Spec{}, fmt.Errorf("range %q: start %d greater than end %d", token, start, end)
			}
			for i := start; i <= end; i++ {
				set[i] = struct{}{}
			}
			continue
		}
		code, err := parseCode(token)
		if err != nil {
			return Spec{}, fmt.Errorf("code %q: %w", token, err)
		}
		set[code] = struct{}{}
	}

	codes := make([]int, 0, len(set))
	for c := range set {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	return Spec{codes: codes}, nil
}

func parseCode(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if n < 100 || n > 599 {
		return 0, fmt.Errorf("out of range (100-599)")
	}
	return n, nil
}

// Codes returns the sorted, deduped codes. Useful for tests and logs.
func (s Spec) Codes() []int {
	out := make([]int, len(s.codes))
	copy(out, s.codes)
	return out
}

// String renders a compact canonical form ("200", "200-204,301").
func (s Spec) String() string {
	if len(s.codes) == 0 {
		return ""
	}
	var parts []string
	i := 0
	for i < len(s.codes) {
		start := s.codes[i]
		end := start
		for i+1 < len(s.codes) && s.codes[i+1] == end+1 {
			end++
			i++
		}
		if start == end {
			parts = append(parts, strconv.Itoa(start))
		} else {
			parts = append(parts, strconv.Itoa(start)+"-"+strconv.Itoa(end))
		}
		i++
	}
	return strings.Join(parts, ",")
}

// CaddyExpectStatus returns the integer to put into Caddy's
// expect_status field plus an optional note describing any lossy
// mapping. A zero return value means "do not set expect_status": the
// active check will accept any response (the caller should also log
// the note as a WARN).
func (s Spec) CaddyExpectStatus() (int, string) {
	if len(s.codes) == 0 {
		return 0, "no codes"
	}
	if len(s.codes) == 1 {
		return s.codes[0], ""
	}

	firstClass := s.codes[0] / 100
	for _, c := range s.codes {
		if c/100 != firstClass {
			return 0, fmt.Sprintf(
				"expect_status %q spans multiple status classes; caddy accepts only one exact code or class, so the active health check will not enforce a specific status",
				s.String(),
			)
		}
	}

	// All codes share a class; if it is the full 100-wide class, emit
	// it losslessly; otherwise flag over-acceptance.
	lo := firstClass * 100
	hi := lo + 99
	if len(s.codes) == 100 && s.codes[0] == lo && s.codes[len(s.codes)-1] == hi {
		return firstClass, ""
	}
	return firstClass, fmt.Sprintf(
		"expect_status %q is a subset of %dxx; caddy's class match will accept any %d00-%d99 response",
		s.String(), firstClass, firstClass, firstClass,
	)
}
