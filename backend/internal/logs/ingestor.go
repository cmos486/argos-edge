// Package logs runs the background pipeline that feeds the unified
// log store: tail Caddy's access/errors files, parse each JSON line,
// batch-write into log_entries, and prune on a schedule.
package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nxadm/tail"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// Ingestor owns the tail goroutines plus a writer that flushes to
// SQLite in batches. Call Start once; Close on shutdown.
type Ingestor struct {
	db          *sql.DB
	accessPath  string
	errorsPath  string
	wafAuditPath string
	ch          chan models.LogEntry
	wg          sync.WaitGroup
	cancel      context.CancelFunc
	accessTail  *tail.Tail
	errorsTail  *tail.Tail
	wafTail     *tail.Tail

	// hostCache maps host_domain -> host_id, populated on demand so the
	// writer does not round-trip to SQL on every access line. Evicted
	// nowhere; the worst case is a restart.
	hostCache sync.Map
}

// NewIngestor prepares (but does not start) an Ingestor. wafAuditPath
// may be "" on panels without phase-4; the ingestor skips the third
// tail in that case.
func NewIngestor(d *sql.DB, accessPath, errorsPath, wafAuditPath string) *Ingestor {
	return &Ingestor{
		db:           d,
		accessPath:   accessPath,
		errorsPath:   errorsPath,
		wafAuditPath: wafAuditPath,
		ch:           make(chan models.LogEntry, 1000),
	}
}

// Start launches the tail goroutines and the writer. If a log file does
// not yet exist the tailer waits and picks it up on creation (nxadm/tail
// MustExist=false behaviour).
func (ing *Ingestor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	ing.cancel = cancel

	// Writer goroutine.
	ing.wg.Add(1)
	go ing.writer(ctx)

	if ing.accessPath != "" {
		t, err := ing.startTail(ing.accessPath, models.LogCaddyAccess)
		if err != nil {
			return err
		}
		ing.accessTail = t
	}
	if ing.errorsPath != "" {
		t, err := ing.startTail(ing.errorsPath, models.LogCaddyError)
		if err != nil {
			return err
		}
		ing.errorsTail = t
	}
	if ing.wafAuditPath != "" {
		t, err := ing.startTail(ing.wafAuditPath, models.LogWAFAudit)
		if err != nil {
			return err
		}
		ing.wafTail = t
	}
	return nil
}

// Close stops the tailers and flushes any pending rows.
func (ing *Ingestor) Close() {
	if ing.accessTail != nil {
		_ = ing.accessTail.Stop()
	}
	if ing.errorsTail != nil {
		_ = ing.errorsTail.Stop()
	}
	if ing.wafTail != nil {
		_ = ing.wafTail.Stop()
	}
	if ing.cancel != nil {
		ing.cancel()
	}
	close(ing.ch)
	ing.wg.Wait()
}

// Enqueue is the entry point the audit recorder uses to push rows
// through the same batching writer as the file tailers.
func (ing *Ingestor) Enqueue(e models.LogEntry) {
	// Non-blocking send with a drop fallback keeps the audit path from
	// stalling if the writer is temporarily saturated. Losing an audit
	// entry is preferable to blocking a login or a hosts CRUD.
	select {
	case ing.ch <- e:
	default:
		slog.Warn("log ingestor channel full, dropping entry",
			"source", e.Source)
	}
}

func (ing *Ingestor) startTail(path string, source models.LogSource) (*tail.Tail, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Create an empty file with permissive mode so tail can
			// attach immediately; otherwise nxadm/tail polls until
			// caddy creates it, which can take a while.
			f, cerr := os.Create(path)
			if cerr == nil {
				f.Close()
			}
		}
	}
	// Seek to end so the panel does not re-ingest the whole file on
	// restart (we would otherwise flood log_entries with duplicates
	// of already-stored rows). Lines written while the panel is down
	// are lost from the DB but remain in caddy_logs for manual audit.
	t, err := tail.TailFile(path, tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: false,
		Poll:      true,
		Logger:    tail.DiscardingLogger,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
	})
	if err != nil {
		return nil, err
	}
	ing.wg.Add(1)
	go ing.consume(t, source)
	return t, nil
}

func (ing *Ingestor) consume(t *tail.Tail, source models.LogSource) {
	defer ing.wg.Done()
	for line := range t.Lines {
		if line.Err != nil {
			slog.Warn("tail error", "source", source, "err", line.Err)
			continue
		}
		// WAF audit lines can fan out to N rows (one per matched rule)
		// so they follow a dedicated parse path that returns a slice.
		if source == models.LogWAFAudit {
			for _, e := range parseWAFLine(line.Text) {
				ing.ch <- e
			}
			continue
		}
		entry, ok := parseLine(line.Text, source)
		if !ok {
			continue
		}
		ing.ch <- entry
	}
}

// resolveHostID looks up the hosts table by domain, caching the id.
// Returns nil when the domain is unknown (row stays with host_id=NULL).
func (ing *Ingestor) resolveHostID(ctx context.Context, domain string) *int64 {
	if domain == "" {
		return nil
	}
	if v, ok := ing.hostCache.Load(domain); ok {
		id := v.(int64)
		if id == 0 {
			return nil
		}
		return &id
	}
	var id int64
	err := ing.db.QueryRowContext(ctx,
		`SELECT id FROM hosts WHERE domain = ? LIMIT 1`, domain,
	).Scan(&id)
	if err != nil {
		ing.hostCache.Store(domain, int64(0))
		return nil
	}
	ing.hostCache.Store(domain, id)
	return &id
}

// writer drains ing.ch, batching inserts.
func (ing *Ingestor) writer(ctx context.Context) {
	defer ing.wg.Done()
	buf := make([]models.LogEntry, 0, 500)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		// Hydrate host_id from host_domain on entries missing it.
		for i := range buf {
			if buf[i].HostID == nil && buf[i].HostDomain != "" {
				buf[i].HostID = ing.resolveHostID(ctx, buf[i].HostDomain)
			}
		}
		if err := db.InsertLogBatch(context.Background(), ing.db, buf); err != nil {
			slog.Error("log batch insert failed",
				"error", err, "rows", len(buf))
		}
		buf = buf[:0]
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case e, ok := <-ing.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, e)
			if len(buf) >= 500 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

// parseLine decodes one JSON line into a LogEntry. Returns false on
// parse failure; the writer logs a WARN and skips.
func parseLine(text string, source models.LogSource) (models.LogEntry, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return models.LogEntry{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return models.LogEntry{}, false
	}
	entry := models.LogEntry{
		Source:    source,
		Timestamp: parseTimestamp(raw),
		Raw:       text,
	}
	switch source {
	case models.LogCaddyAccess:
		fillAccess(&entry, raw)
	case models.LogCaddyError:
		fillError(&entry, raw)
	case models.LogWAFAudit:
		// A single Coraza transaction can match several rules; the
		// parser emits one LogEntry per message. The returned entry
		// is the FIRST message; additional ones are handed back via
		// the Ingestor.parseWAFExtra slice so the caller can enqueue
		// them. For a no-match transaction the parser returns the
		// transaction stub (status/host/path populated, waf fields 0)
		// so the operator can still trace "request X saw no rule".
		fillWAFFirst(&entry, raw)
	}
	return entry, true
}

// parseWAFLine replaces the generic path for waf_audit lines: returns
// a slice of entries (one per rule match, or a single stub if none).
func parseWAFLine(text string) []models.LogEntry {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil
	}
	tx := nested(raw, "transaction")
	base := models.LogEntry{
		Source:    models.LogWAFAudit,
		Timestamp: parseTimestamp(tx),
		Raw:       text,
	}
	if base.Timestamp.IsZero() {
		base.Timestamp = parseTimestamp(raw)
	}
	fillWAFCommon(&base, tx)

	msgs, _ := tx["messages"].([]any)
	if len(msgs) == 0 {
		return []models.LogEntry{base}
	}
	out := make([]models.LogEntry, 0, len(msgs))
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		e := base
		fillWAFMessage(&e, mm)
		out = append(out, e)
	}
	return out
}

func fillWAFFirst(e *models.LogEntry, raw map[string]any) {
	tx := nested(raw, "transaction")
	fillWAFCommon(e, tx)
	msgs, _ := tx["messages"].([]any)
	if len(msgs) > 0 {
		if mm, ok := msgs[0].(map[string]any); ok {
			fillWAFMessage(e, mm)
		}
	}
}

// fillWAFCommon extracts the per-transaction fields (client IP, method,
// path, host, status) from Coraza's audit log.
func fillWAFCommon(e *models.LogEntry, tx map[string]any) {
	e.RemoteIP = firstStr(tx["client_ip"])
	req := nested(tx, "request")
	e.Method = firstStr(req["method"])
	uri := firstStr(req["uri"])
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	e.Path = uri
	// host is in request.headers.Host
	if h := headersFirst(nested(req, "headers"), "Host"); h != "" {
		e.HostDomain = h
	}
	resp := nested(tx, "response")
	if st, ok := resp["status"].(float64); ok {
		e.Status = int(st)
	}
}

// fillWAFMessage fills the rule-specific fields from one message entry.
func fillWAFMessage(e *models.LogEntry, m map[string]any) {
	if id := firstStr(m["id"]); id != "" {
		if n, err := strconv.Atoi(id); err == nil {
			e.WAFRuleID = n
		}
	}
	e.WAFRuleMessage = firstStr(m["message"])
	e.Message = e.WAFRuleMessage
	e.Level = "error"
	if s, ok := m["severity"].(float64); ok {
		e.WAFSeverity = severityName(int(s))
	} else if s := firstStr(m["severity"]); s != "" {
		e.WAFSeverity = s
	}
}

// severityName maps Coraza's 0-6 severity int to the ModSecurity names.
func severityName(n int) string {
	switch n {
	case 0:
		return "EMERGENCY"
	case 1:
		return "ALERT"
	case 2:
		return "CRITICAL"
	case 3:
		return "ERROR"
	case 4:
		return "WARNING"
	case 5:
		return "NOTICE"
	case 6:
		return "INFO"
	default:
		return ""
	}
}

func parseTimestamp(raw map[string]any) time.Time {
	if v, ok := raw["ts"]; ok {
		switch n := v.(type) {
		case float64:
			sec, frac := int64(n), n-float64(int64(n))
			return time.Unix(sec, int64(frac*1e9)).UTC()
		case string:
			if t, err := time.Parse(time.RFC3339Nano, n); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Now().UTC()
}

// fillAccess extracts the standard Caddy access-log fields. The
// header-injected X-Argos-Host-Id / X-Argos-Rule-Id / X-Argos-Target-
// Group land in request.headers so we pick them up here.
func fillAccess(e *models.LogEntry, raw map[string]any) {
	req := nested(raw, "request")
	headers := nested(req, "headers")

	e.RemoteIP = firstStr(req["remote_ip"])
	e.Method = firstStr(req["method"])
	e.HostDomain = firstStr(req["host"])
	e.Path = firstStr(req["uri"])
	if i := strings.IndexByte(e.Path, '?'); i >= 0 {
		e.Path = e.Path[:i]
	}
	if ua := headersFirst(headers, "User-Agent"); ua != "" {
		e.UserAgent = ua
	}
	if hid := headersFirst(headers, "X-Argos-Host-Id"); hid != "" {
		if n, err := strconv.ParseInt(hid, 10, 64); err == nil && n > 0 {
			e.HostID = &n
		}
	}
	if rid := headersFirst(headers, "X-Argos-Rule-Id"); rid != "" {
		if n, err := strconv.ParseInt(rid, 10, 64); err == nil && n > 0 {
			e.RuleID = &n
		}
	}
	if tg := headersFirst(headers, "X-Argos-Target-Group"); tg != "" {
		e.Upstream = tg
	}

	if st, ok := raw["status"].(float64); ok {
		e.Status = int(st)
	}
	if sz, ok := raw["size"].(float64); ok {
		e.SizeBytes = int(sz)
	}
	if dur, ok := raw["duration"].(float64); ok {
		e.DurationMs = int(dur * 1000)
	}
}

// fillError maps caddy's generic zap output (logger/msg/level) into
// the shared schema. Many errors have no http context; what is there
// (e.g. tls.obtain "error" messages) gets captured in Message.
func fillError(e *models.LogEntry, raw map[string]any) {
	e.Level = firstStr(raw["level"])
	e.Message = firstStr(raw["msg"])
	if errStr := firstStr(raw["error"]); errStr != "" {
		if e.Message == "" {
			e.Message = errStr
		} else {
			e.Message += " -- " + errStr
		}
	}
	if logger := firstStr(raw["logger"]); logger != "" && e.Message != "" {
		e.Message = logger + ": " + e.Message
	}
	if id := firstStr(raw["identifier"]); id != "" {
		e.HostDomain = id
	}
}

// nested returns m[key] as a map or an empty map.
func nested(m map[string]any, key string) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func firstStr(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case []any:
		if len(n) > 0 {
			return firstStr(n[0])
		}
	}
	return ""
}

// headersFirst handles Caddy's request.headers which is a
// map[name][]string.
func headersFirst(h map[string]any, name string) string {
	if h == nil {
		return ""
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return firstStr(v)
		}
	}
	return ""
}
