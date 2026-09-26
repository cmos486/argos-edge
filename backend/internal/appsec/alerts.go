package appsec

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// One LAPI source for every AppSec consumer (v1.3.39).
//
// The Dashboard security section (pinned, refreshed every 24 s), the
// Security overview, the AppSec page (windows 1h to 24h) and the WAF
// burst notifications all read the same cached fetch: one
// GET /v1/alerts for the last 24 h (30 s TTL) and, only when a 7 d
// view asks for it, one for the last 7 d (60 s TTL). Nothing fetches
// the same data twice. Measured on prod 2026-09-26: 24 h = 259 alerts
// / 0.7 MB / 0.09 s, 7 d = 1,270 alerts / 4.2 MB / 0.67 s.
//
// "AppSec alert" here means kind=waf (one alert per blocked or
// detected request, a "hit") or one of the appsec-* ban scenarios of
// kind=crowdsec (a bucket overflow that produced a decision, a
// "ban"). That is the definition the AppSec page has used since
// v1.3.4; hits and bans are now reported separately as well.
const (
	alertsWindowShort = 24 * time.Hour
	alertsWindowLong  = 7 * 24 * time.Hour
	alertsTTLShort    = 30 * time.Second
	alertsTTLLong     = 60 * time.Second
	// alertsFallbackAt is the fetch size at which the 7 d window is
	// assumed truncated by the limit and re-fetched as seven 24 h
	// windows (since/until are relative, so the windows are exact).
	alertsFallbackAt = crowdsec.DefaultAlertsLimit

	burstWindow = 60 * time.Second
	burstThresh = 10
)

// Notifier is the subset of notifications.Emitter the burst detector
// needs.
type Notifier interface {
	Emit(ev notifications.Event)
}

type alertSet struct {
	alerts []crowdsec.Alert
	at     time.Time
	err    error
}

// alertsCache is the per-fetch-window state; one mutex per window so
// a 7 d fetch does not hold the 24 h callers.
type alertsCache struct {
	mu  sync.Mutex
	set alertSet
}

// IsAppSecAlert reports whether a is an AppSec alert (hit or ban).
func IsAppSecAlert(a crowdsec.Alert) bool {
	return a.Kind == "waf" || looksLikeAppSec(a.Scenario)
}

// IsBan reports whether an AppSec alert is a ban (bucket overflow with
// a decision) rather than a request-level hit.
func IsBan(a crowdsec.Alert) bool {
	return a.Kind != "waf" && looksLikeAppSec(a.Scenario)
}

// SetNotifier wires the burst detector. Bursts are only looked for in
// alerts newer than this call, so a restart does not re-notify
// history.
func (p *Provider) SetNotifier(n Notifier) {
	p.mu.Lock()
	p.notifier = n
	p.burstSince = time.Now().UTC()
	if p.lastBurst == nil {
		p.lastBurst = map[string]time.Time{}
	}
	p.mu.Unlock()
}

// Alerts returns the AppSec alerts created in the last window (newest
// first, as the LAPI orders them) and the time the underlying fetch
// was made. Windows up to 24 h are served from the 24 h fetch; longer
// windows from the 7 d fetch.
func (p *Provider) Alerts(ctx context.Context, window time.Duration) ([]crowdsec.Alert, time.Time, error) {
	if p.CS == nil {
		return nil, time.Time{}, crowdsec.ErrNotConfigured
	}
	// The dashboard's 24 h range arrives as 24 h plus the bucket snap
	// of its `from` (up to 1 h); that is still the short fetch.
	fetchWindow, ttl, cache := alertsWindowShort, alertsTTLShort, &p.short
	if window > alertsWindowShort+time.Hour {
		fetchWindow, ttl, cache = alertsWindowLong, alertsTTLLong, &p.long
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.set.at.IsZero() || time.Since(cache.set.at) >= ttl {
		alerts, err := p.fetch(ctx, fetchWindow)
		if err != nil && len(cache.set.alerts) > 0 {
			// Keep serving the last good set for one more TTL instead
			// of retrying the LAPI on every call; the error is kept so
			// a caller with no data at all still sees it.
			cache.set = alertSet{alerts: cache.set.alerts, at: time.Now().UTC(), err: err}
		} else {
			cache.set = alertSet{alerts: alerts, at: time.Now().UTC(), err: err}
			if err == nil && fetchWindow == alertsWindowShort {
				p.detectBursts(alerts, cache.set.at)
			}
		}
	}
	if cache.set.err != nil && len(cache.set.alerts) == 0 {
		return nil, time.Time{}, cache.set.err
	}
	return filterWindow(cache.set.alerts, window, time.Now().UTC()), cache.set.at, nil
}

// fetch runs the LAPI query for fetchWindow and keeps the AppSec
// alerts. A 7 d fetch that fills the limit is re-done as seven exact
// 24 h windows (the LAPI has no pagination; since/until are relative
// durations, so each window is [now-(k+1)d, now-kd]).
func (p *Provider) fetch(ctx context.Context, fetchWindow time.Duration) ([]crowdsec.Alert, error) {
	raw, err := p.CS.QueryAlerts(ctx, crowdsec.AlertsQuery{Since: fetchWindow})
	if err != nil {
		return nil, err
	}
	if fetchWindow > alertsWindowShort && len(raw) >= alertsFallbackAt {
		raw, err = p.fetchByDays(ctx, fetchWindow)
		if err != nil {
			return nil, err
		}
	}
	out := make([]crowdsec.Alert, 0, len(raw))
	for _, a := range raw {
		if IsAppSecAlert(a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (p *Provider) fetchByDays(ctx context.Context, fetchWindow time.Duration) ([]crowdsec.Alert, error) {
	days := int((fetchWindow + 24*time.Hour - 1) / (24 * time.Hour))
	seen := map[int64]bool{}
	var out []crowdsec.Alert
	for k := 0; k < days; k++ {
		q := crowdsec.AlertsQuery{Since: time.Duration(k+1) * 24 * time.Hour}
		if k > 0 {
			q.Until = time.Duration(k) * 24 * time.Hour
		}
		list, err := p.CS.QueryAlerts(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, a := range list {
			if !seen[a.ID] {
				seen[a.ID] = true
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func filterWindow(alerts []crowdsec.Alert, window time.Duration, now time.Time) []crowdsec.Alert {
	cutoff := now.Add(-window)
	out := make([]crowdsec.Alert, 0, len(alerts))
	for _, a := range alerts {
		ts := a.StartedAt()
		if ts.IsZero() || !ts.Before(cutoff) {
			out = append(out, a)
		}
	}
	return out
}

// detectBursts emits one waf_attack_burst per source IP whose kind=waf
// alerts reach burstThresh inside burstWindow, the same rule the log
// watcher applies to Coraza audit rows. Only alerts newer than the
// previous scan (minus one window, so a burst straddling two scans is
// seen once) are considered; lastBurst de-duplicates across scans.
func (p *Provider) detectBursts(alerts []crowdsec.Alert, now time.Time) {
	p.mu.Lock()
	n := p.notifier
	since := p.burstSince
	p.mu.Unlock()
	if n == nil {
		return
	}
	byIP := map[string][]crowdsec.Alert{}
	for _, a := range alerts {
		if a.Kind != "waf" {
			continue
		}
		ts := a.StartedAt()
		if ts.IsZero() || ts.Before(since.Add(-burstWindow)) {
			continue
		}
		ip := a.Source.Value
		if ip == "" {
			ip = a.Source.IP
		}
		if ip == "" {
			continue
		}
		byIP[ip] = append(byIP[ip], a)
	}
	for ip, list := range byIP {
		if len(list) < burstThresh {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].StartedAt().Before(list[j].StartedAt()) })
		i := 0
		for j := range list {
			for list[j].StartedAt().Sub(list[i].StartedAt()) > burstWindow {
				i++
			}
			if j-i+1 < burstThresh {
				continue
			}
			end := list[j].StartedAt()
			p.mu.Lock()
			dup := !end.After(p.lastBurst[ip])
			if !dup {
				p.lastBurst[ip] = end
			}
			p.mu.Unlock()
			if dup {
				break
			}
			n.Emit(notifications.Event{
				Type:       notifications.EvtWAFAttackBurst,
				Severity:   notifications.SeverityCritical,
				HostDomain: list[j].EventMeta()["target_fqdn"],
				Timestamp:  end,
				Message:    "attack burst from " + ip + " (AppSec)",
				Data: map[string]any{
					"remote_ip":      ip,
					"count":          j - i + 1,
					"window_seconds": int(burstWindow.Seconds()),
					"engine":         "appsec",
				},
			})
			break
		}
	}
	p.mu.Lock()
	p.burstSince = now
	p.mu.Unlock()
}

// Summary is the per-window aggregation of AppSec alerts the Dashboard
// security section and the Security overview merge with the Coraza
// (waf_audit) figures. Keys of the host maps are the lower-cased
// target_fqdn of the alert's events.
type Summary struct {
	Hits, Bans      int
	Blocked, Logged int // by classifyOutcome (mode boundary; see api.md)
	HitsByHost      map[string]int
	LastByHost      map[string]time.Time
	ByIP            map[string]int
	LastByIP        map[string]time.Time
	HostsByIP       map[string]map[string]struct{}
	ByRule          map[string]int
	RuleMsg         map[string]string
	ByPath          map[[2]string]int // {host, path}
	Buckets         map[int64]Outcome // bucket start unix -> counts
}

// Outcome is one time bucket's detected / blocked split.
type Outcome struct {
	Detected, Blocked int
}

// HostOf returns the lower-cased target_fqdn of an alert, "" if none.
func HostOf(a crowdsec.Alert) string {
	return strings.ToLower(a.EventMeta()["target_fqdn"])
}

// Summarize aggregates alerts created in [from, to] into g-sized
// buckets. mode / prevMode / lastChangeAt drive the blocked vs logged
// attribution exactly as Metrics does.
func Summarize(alerts []crowdsec.Alert, from, to time.Time, g time.Duration, mode, prevMode, lastChangeAt string) Summary {
	s := Summary{
		HitsByHost: map[string]int{}, LastByHost: map[string]time.Time{},
		ByIP: map[string]int{}, LastByIP: map[string]time.Time{}, HostsByIP: map[string]map[string]struct{}{},
		ByRule: map[string]int{}, RuleMsg: map[string]string{},
		ByPath: map[[2]string]int{}, Buckets: map[int64]Outcome{},
	}
	var boundary time.Time
	if lastChangeAt != "" {
		if t, err := time.Parse(time.RFC3339, lastChangeAt); err == nil {
			boundary = t.UTC()
		}
	}
	for _, a := range alerts {
		if !IsAppSecAlert(a) {
			continue
		}
		ts := a.StartedAt()
		if !ts.IsZero() && (ts.Before(from) || ts.After(to)) {
			continue
		}
		blocked := classifyOutcome(a, mode, prevMode, boundary)
		if blocked {
			s.Blocked++
		} else {
			s.Logged++
		}
		meta := a.EventMeta()
		host := strings.ToLower(meta["target_fqdn"])
		if IsBan(a) {
			s.Bans++
		} else {
			s.Hits++
			if host != "" {
				s.HitsByHost[host]++
				if ts.After(s.LastByHost[host]) {
					s.LastByHost[host] = ts
				}
			}
		}
		ip := a.Source.Value
		if ip == "" {
			ip = a.Source.IP
		}
		if ip != "" {
			s.ByIP[ip]++
			if ts.After(s.LastByIP[ip]) {
				s.LastByIP[ip] = ts
			}
			if host != "" {
				if s.HostsByIP[ip] == nil {
					s.HostsByIP[ip] = map[string]struct{}{}
				}
				s.HostsByIP[ip][host] = struct{}{}
			}
		}
		s.ByRule[a.Scenario]++
		if _, ok := s.RuleMsg[a.Scenario]; !ok {
			s.RuleMsg[a.Scenario] = meta["message"]
		}
		if uri := meta["uri"]; uri != "" {
			s.ByPath[[2]string{host, uri}]++
		}
		if !ts.IsZero() && g > 0 {
			k := ts.Truncate(g).Unix()
			o := s.Buckets[k]
			if blocked {
				o.Blocked++
			} else {
				o.Detected++
			}
			s.Buckets[k] = o
		}
	}
	return s
}
