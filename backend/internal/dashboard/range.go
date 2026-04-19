package dashboard

import (
	"fmt"
	"time"
)

// supportedRanges enumerates the four time windows the UI exposes.
// The companion granularity is picked so every range returns a
// similar number of buckets (~60-168) that a chart can render
// without overcrowding.
var supportedRanges = map[string]struct {
	Window      time.Duration
	Granularity time.Duration
	Label       string // returned to the client for debug/UI
}{
	"1h":  {time.Hour, time.Minute, "1m"},
	"6h":  {6 * time.Hour, 5 * time.Minute, "5m"},
	"24h": {24 * time.Hour, 15 * time.Minute, "15m"},
	"7d":  {7 * 24 * time.Hour, time.Hour, "1h"},
}

// ParseRange validates the range string and returns (from, to, g, label).
// Returns an error on unknown values.
func ParseRange(s string) (from, to time.Time, g time.Duration, label string, err error) {
	cfg, ok := supportedRanges[s]
	if !ok {
		return time.Time{}, time.Time{}, 0, "", fmt.Errorf("unknown range %q; expected one of 1h, 6h, 24h, 7d", s)
	}
	to = time.Now().UTC()
	from = to.Add(-cfg.Window)
	// Snap `from` down to the nearest bucket boundary so the first
	// bucket is full-width rather than a partial slice.
	from = from.Truncate(cfg.Granularity)
	return from, to, cfg.Granularity, cfg.Label, nil
}

// bucketTimes returns the sequence of bucket start times between from
// and to at step g. Used to fill zeros for empty buckets in charts so
// the UI draws a continuous line.
func bucketTimes(from, to time.Time, g time.Duration) []time.Time {
	if g <= 0 {
		return nil
	}
	// snap from to grid
	from = from.Truncate(g)
	n := int(to.Sub(from)/g) + 1
	if n <= 0 {
		return nil
	}
	out := make([]time.Time, 0, n)
	for t := from; !t.After(to); t = t.Add(g) {
		out = append(out, t)
	}
	return out
}
