package api

import (
	"strings"
	"time"
)

// rangePresets is the URL vocabulary's `range` (v1.3.42.1 on the
// client, v1.3.42.3 on the endpoints): the presets every page mounts a
// subset of. Endpoints that take from/to accept `range` as the
// alternative; from/to win when present.
var rangePresets = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"12h": 12 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// parseRangeParam decodes a `range` preset; false for anything else.
func parseRangeParam(s string) (time.Duration, bool) {
	d, ok := rangePresets[strings.ToLower(strings.TrimSpace(s))]
	return d, ok
}
