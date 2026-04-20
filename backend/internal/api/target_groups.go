package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/caddycfg/expectstatus"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// hostOrIPRE accepts a lowercase label sequence (FQDN-ish) or a
// literal IPv4. IPv6 would need brackets elsewhere; phase 2 scope is
// LAN backends where v4 / hostnames are enough.
var hostOrIPRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$`)

// --- requests ---

type targetGroupRequest struct {
	Name                        string               `json:"name"`
	Protocol                    string               `json:"protocol"`
	VerifyTLS                   *bool                `json:"verify_tls,omitempty"`
	Algorithm                   string               `json:"algorithm"`
	HealthCheckEnabled          *bool                `json:"health_check_enabled,omitempty"`
	HealthCheckPath             string               `json:"health_check_path"`
	HealthCheckMethod           string               `json:"health_check_method"`
	HealthCheckExpectStatus     string               `json:"health_check_expect_status"`
	HealthCheckIntervalSeconds  int                  `json:"health_check_interval_seconds"`
	HealthCheckTimeoutSeconds   int                  `json:"health_check_timeout_seconds"`
	HealthCheckFailsToUnhealthy int                  `json:"health_check_fails_to_unhealthy"`
	HealthCheckPassesToHealthy  int                  `json:"health_check_passes_to_healthy"`
	Targets                     []targetInputRequest `json:"targets,omitempty"`
}

type targetInputRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  *int   `json:"weight,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// --- list + get ---

func (h *Handlers) ListTargetGroups(w http.ResponseWriter, r *http.Request) {
	tgs, err := db.ListTargetGroups(r.Context(), h.DB, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list target groups failed")
		return
	}
	if tgs == nil {
		tgs = []models.TargetGroup{}
	}
	writeJSON(w, http.StatusOK, tgs)
}

func (h *Handlers) GetTargetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	tg, err := db.GetTargetGroup(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrTargetGroupNotFound) {
			writeError(w, http.StatusNotFound, "target group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get target group failed")
		return
	}
	writeJSON(w, http.StatusOK, tg)
}

// --- create ---

func (h *Handlers) CreateTargetGroup(w http.ResponseWriter, r *http.Request) {
	var req targetGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	tg, initial, msg := req.toTargetGroup(0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	created, err := db.CreateTargetGroup(r.Context(), h.DB, tg, initial)
	if err != nil {
		if errors.Is(err, db.ErrTargetGroupNameTaken) {
			writeError(w, http.StatusConflict, "target group name already taken")
			return
		}
		if errors.Is(err, db.ErrTargetDuplicate) {
			writeError(w, http.StatusConflict, "duplicate target in group (host+port)")
			return
		}
		writeError(w, http.StatusInternalServerError, "create target group failed")
		return
	}
	h.audit(r, "create", "target_group", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

// --- update ---

func (h *Handlers) UpdateTargetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req targetGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	tg, _, msg := req.toTargetGroup(id)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	updated, err := db.UpdateTargetGroup(r.Context(), h.DB, tg)
	if err != nil {
		if errors.Is(err, db.ErrTargetGroupNotFound) {
			writeError(w, http.StatusNotFound, "target group not found")
			return
		}
		if errors.Is(err, db.ErrTargetGroupNameTaken) {
			writeError(w, http.StatusConflict, "target group name already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "update target group failed")
		return
	}
	h.audit(r, "update", "target_group", updated.ID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// --- delete ---

func (h *Handlers) DeleteTargetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := db.DeleteTargetGroup(r.Context(), h.DB, id); err != nil {
		if errors.Is(err, db.ErrTargetGroupNotFound) {
			writeError(w, http.StatusNotFound, "target group not found")
			return
		}
		if errors.Is(err, db.ErrTargetGroupInUse) {
			n, _ := db.CountHostsUsingTargetGroup(r.Context(), h.DB, id)
			writeError(w, http.StatusConflict, fmt.Sprintf("target group in use by %d hosts", n))
			return
		}
		writeError(w, http.StatusInternalServerError, "delete target group failed")
		return
	}
	h.audit(r, "delete", "target_group", id, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// --- targets subroutes ---

func (h *Handlers) AddTarget(w http.ResponseWriter, r *http.Request) {
	tgID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req targetInputRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	t, msg := req.toTarget(0, tgID)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	created, err := db.AddTarget(r.Context(), h.DB, t)
	if err != nil {
		if errors.Is(err, db.ErrTargetGroupNotFound) {
			writeError(w, http.StatusNotFound, "target group not found")
			return
		}
		if errors.Is(err, db.ErrTargetDuplicate) {
			writeError(w, http.StatusConflict, "target with same host+port already in group")
			return
		}
		writeError(w, http.StatusInternalServerError, "add target failed")
		return
	}
	h.audit(r, "create", "target", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	_, ok := parseIDParam(w, r, "id") // tgID reserved for future audit
	if !ok {
		return
	}
	tid, ok := parseIDParam(w, r, "target_id")
	if !ok {
		return
	}
	var req targetInputRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	t, msg := req.toTarget(tid, 0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	updated, err := db.UpdateTarget(r.Context(), h.DB, t)
	if err != nil {
		if errors.Is(err, db.ErrTargetNotFound) {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		if errors.Is(err, db.ErrTargetDuplicate) {
			writeError(w, http.StatusConflict, "target with same host+port already in group")
			return
		}
		writeError(w, http.StatusInternalServerError, "update target failed")
		return
	}
	h.audit(r, "update", "target", updated.ID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handlers) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	if _, ok := parseIDParam(w, r, "id"); !ok {
		return
	}
	tid, ok := parseIDParam(w, r, "target_id")
	if !ok {
		return
	}
	if err := db.DeleteTarget(r.Context(), h.DB, tid); err != nil {
		if errors.Is(err, db.ErrTargetNotFound) {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete target failed")
		return
	}
	h.audit(r, "delete", "target", tid, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ToggleTarget(w http.ResponseWriter, r *http.Request) {
	if _, ok := parseIDParam(w, r, "id"); !ok {
		return
	}
	tid, ok := parseIDParam(w, r, "target_id")
	if !ok {
		return
	}
	t, err := db.ToggleTarget(r.Context(), h.DB, tid)
	if err != nil {
		if errors.Is(err, db.ErrTargetNotFound) {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "toggle target failed")
		return
	}
	h.audit(r, "toggle", "target", t.ID, map[string]any{"enabled": t.Enabled})
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, t)
}

// --- request validation ---

// toTargetGroup validates and normalises the incoming TG payload. The
// returned slice is the initial targets to create (POST /api/target-groups
// may include some; PUT updates only TG config so the caller ignores it).
func (req *targetGroupRequest) toTargetGroup(id int64) (models.TargetGroup, []models.Target, string) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return models.TargetGroup{}, nil, "name is required"
	}
	if len(name) > 63 {
		return models.TargetGroup{}, nil, "name too long (max 63)"
	}

	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = string(models.ProtocolHTTP)
	}
	if proto != string(models.ProtocolHTTP) && proto != string(models.ProtocolHTTPS) {
		return models.TargetGroup{}, nil, `protocol must be "http" or "https"`
	}

	algo := strings.ToLower(strings.TrimSpace(req.Algorithm))
	if algo == "" {
		algo = string(models.AlgoRoundRobin)
	}
	switch models.Algorithm(algo) {
	case models.AlgoRoundRobin, models.AlgoLeastConn, models.AlgoIPHash, models.AlgoRandom:
	default:
		return models.TargetGroup{}, nil,
			`algorithm must be one of: round_robin, least_conn, ip_hash, random`
	}

	hcEnabled := false
	if req.HealthCheckEnabled != nil {
		hcEnabled = *req.HealthCheckEnabled
	}

	hcPath := req.HealthCheckPath
	if strings.TrimSpace(hcPath) == "" {
		hcPath = "/"
	}
	if !strings.HasPrefix(hcPath, "/") {
		return models.TargetGroup{}, nil, "health_check_path must start with /"
	}

	method := strings.ToUpper(strings.TrimSpace(req.HealthCheckMethod))
	if method == "" {
		method = "GET"
	}
	switch models.HealthCheckMethod(method) {
	case models.HealthGet, models.HealthHead, models.HealthPost:
	default:
		return models.TargetGroup{}, nil, "health_check_method must be GET, HEAD or POST"
	}

	expect := strings.TrimSpace(req.HealthCheckExpectStatus)
	if expect == "" {
		expect = "200"
	}
	spec, err := expectstatus.Parse(expect)
	if err != nil {
		return models.TargetGroup{}, nil,
			fmt.Sprintf("health_check_expect_status invalid: %v", err)
	}
	// Caddy's JSON active check accepts a single int (exact code or
	// 1-5xx class). A multi-class list would silently degrade to "no
	// status check"; reject at the edge so operators notice.
	if spec.SpansMultipleClasses() {
		return models.TargetGroup{}, nil,
			`health_check_expect_status cannot mix different status classes (e.g. 200,301): caddy's JSON active check only supports a single exact code or a 1xx-5xx class. Use a single code, a single class range, or create separate target groups.`
	}

	interval := req.HealthCheckIntervalSeconds
	if interval == 0 {
		interval = 30
	}
	if interval < 5 || interval > 300 {
		return models.TargetGroup{}, nil,
			"health_check_interval_seconds must be between 5 and 300"
	}

	timeout := req.HealthCheckTimeoutSeconds
	if timeout == 0 {
		timeout = 5
	}
	if timeout < 1 || timeout > 30 {
		return models.TargetGroup{}, nil,
			"health_check_timeout_seconds must be between 1 and 30"
	}

	fails := req.HealthCheckFailsToUnhealthy
	if fails == 0 {
		fails = 2
	}
	if fails < 1 || fails > 10 {
		return models.TargetGroup{}, nil,
			"health_check_fails_to_unhealthy must be between 1 and 10"
	}

	passes := req.HealthCheckPassesToHealthy
	if passes == 0 {
		passes = 2
	}
	if passes < 1 || passes > 10 {
		return models.TargetGroup{}, nil,
			"health_check_passes_to_healthy must be between 1 and 10"
	}

	verify := true
	if req.VerifyTLS != nil {
		verify = *req.VerifyTLS
	}

	tg := models.TargetGroup{
		ID:                          id,
		Name:                        name,
		Protocol:                    models.Protocol(proto),
		VerifyTLS:                   verify,
		Algorithm:                   models.Algorithm(algo),
		HealthCheckEnabled:          hcEnabled,
		HealthCheckPath:             hcPath,
		HealthCheckMethod:           models.HealthCheckMethod(method),
		HealthCheckExpectStatus:     expect,
		HealthCheckIntervalSeconds:  interval,
		HealthCheckTimeoutSeconds:   timeout,
		HealthCheckFailsToUnhealthy: fails,
		HealthCheckPassesToHealthy:  passes,
	}

	var targets []models.Target
	seen := map[string]struct{}{}
	for i, tr := range req.Targets {
		t, msg := tr.toTarget(0, 0)
		if msg != "" {
			return models.TargetGroup{}, nil, fmt.Sprintf("targets[%d]: %s", i, msg)
		}
		key := fmt.Sprintf("%s:%d", t.Host, t.Port)
		if _, dup := seen[key]; dup {
			return models.TargetGroup{}, nil,
				fmt.Sprintf("targets[%d]: duplicate %s in request", i, key)
		}
		seen[key] = struct{}{}
		targets = append(targets, t)
	}
	return tg, targets, ""
}

func (req *targetInputRequest) toTarget(id, tgID int64) (models.Target, string) {
	host := strings.ToLower(strings.TrimSpace(req.Host))
	if host == "" {
		return models.Target{}, "host is required"
	}
	// Accept IPs (v4 or v6) or anything matching a loose hostname regex.
	if net.ParseIP(host) == nil && !hostOrIPRE.MatchString(host) {
		return models.Target{}, "host must be an FQDN or IP"
	}

	if req.Port < 1 || req.Port > 65535 {
		return models.Target{}, "port must be between 1 and 65535"
	}

	weight := 1
	if req.Weight != nil {
		weight = *req.Weight
	}
	if weight < 1 || weight > 256 {
		return models.Target{}, "weight must be between 1 and 256"
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return models.Target{
		ID:            id,
		TargetGroupID: tgID,
		Host:          host,
		Port:          req.Port,
		Weight:        weight,
		Enabled:       enabled,
	}, ""
}

// parseIDParam overrides the helper in hosts.go to accept a named param
// (needed now that we have both {id} and {target_id} on the same route).
func parseIDParam(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := chi.URLParam(r, name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid %s", name))
		return 0, false
	}
	return id, true
}

