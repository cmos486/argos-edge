package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/configio"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

func (h *Handlers) requireBackup(w http.ResponseWriter) bool {
	if h.BackupMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "backup manager not wired")
		return false
	}
	return true
}

// --- /api/backups ---

func (h *Handlers) ListBackups(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	list, err := h.BackupMgr.List(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	if list == nil {
		list = []backup.Backup{}
	}
	writeJSON(w, http.StatusOK, list)
}

type createBackupBody struct {
	Note string `json:"note"`
}

func (h *Handlers) CreateBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	var body createBackupBody
	if r.ContentLength > 0 {
		_ = decodeJSON(r, &body)
	}
	u, _ := userFromContext(r.Context())
	var uid *int64
	if u.ID > 0 {
		v := u.ID
		uid = &v
	}
	b, err := h.BackupMgr.Create(r.Context(), "manual", body.Note, uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	h.audit(r, "create", "backup", b.ID, map[string]any{"filename": b.Filename, "size": b.SizeBytes})
	// emit notification
	if h.NotifWorker != nil && h.NotifRepo != nil {
		if em := h.emitterForBackup(); em != nil {
			em.Emit(notifications.Event{
				Type:     notifications.EvtBackupCompleted,
				Severity: notifications.SeverityInfo,
				Message:  fmt.Sprintf("manual backup %s (%d bytes) ok", b.Filename, b.SizeBytes),
				Data: map[string]any{
					"filename":   b.Filename,
					"size_bytes": b.SizeBytes,
					"kind":       "manual",
				},
			})
		}
	}
	writeJSON(w, http.StatusCreated, b)
}

// emitterForBackup returns the emitter if plumbed through; the API
// layer does not take a direct dependency on the emitter field, so
// main wires it via the worker (the worker has the emitter).
func (h *Handlers) emitterForBackup() *notifications.Emitter {
	return h.NotifEmitter
}

func (h *Handlers) GetBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	b, err := h.BackupMgr.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, backup.ErrBackupNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (h *Handlers) DownloadBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	b, err := h.BackupMgr.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, backup.ErrBackupNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := filepath.Join(h.BackupMgr.BackupDir, b.Filename)
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "open: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, b.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(b.SizeBytes, 10))
	_, _ = io.Copy(w, f)
}

func (h *Handlers) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.BackupMgr.Delete(r.Context(), id); err != nil {
		if errors.Is(err, backup.ErrBackupNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "delete", "backup", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

type restoreBody struct {
	Confirm bool `json:"confirm"`
}

func (h *Handlers) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body restoreBody
	if r.ContentLength > 0 {
		_ = decodeJSON(r, &body)
	}
	if !body.Confirm {
		writeError(w, http.StatusBadRequest, "confirm=true required")
		return
	}
	b, err := h.BackupMgr.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, backup.ErrBackupNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := filepath.Join(h.BackupMgr.BackupDir, b.Filename)
	plan, err := h.BackupMgr.Prepare(r.Context(), path, b.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "prepare: "+err.Error())
		return
	}
	if err := h.BackupMgr.Apply(plan); err != nil {
		writeError(w, http.StatusInternalServerError, "apply: "+err.Error())
		return
	}
	h.audit(r, "update", "backup", id, map[string]any{"action": "restore", "filename": b.Filename})
	// respond 202 then bounce
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"scheduled": true,
		"backup":    b,
		"warnings":  plan.Warnings,
		"message":   "Restore scheduled. Server will restart; reload in ~15s.",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// give the response a tick to reach the client, then exit so
	// docker restart-policy kicks in and the next boot picks up the
	// restore flag file.
	go func() {
		time.Sleep(800 * time.Millisecond)
		os.Exit(0)
	}()
}

func (h *Handlers) UploadAndRestore(w http.ResponseWriter, r *http.Request) {
	if !h.requireBackup(w) {
		return
	}
	// Cap upload to 500 MiB to avoid accidental oom.
	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "parse multipart: "+err.Error())
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file required")
		return
	}
	defer file.Close()

	confirm := r.FormValue("confirm")
	if confirm != "true" {
		writeError(w, http.StatusBadRequest, "confirm=true required")
		return
	}

	tmp := filepath.Join(h.BackupMgr.BackupDir, ".upload-"+hdr.Filename)
	out, err := os.Create(tmp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stage: "+err.Error())
		return
	}
	_, copyErr := io.Copy(out, file)
	out.Close()
	if copyErr != nil {
		os.Remove(tmp)
		writeError(w, http.StatusInternalServerError, "store upload: "+copyErr.Error())
		return
	}
	plan, err := h.BackupMgr.Prepare(r.Context(), tmp, 0)
	if err != nil {
		os.Remove(tmp)
		writeError(w, http.StatusBadRequest, "prepare: "+err.Error())
		return
	}
	if err := h.BackupMgr.Apply(plan); err != nil {
		os.Remove(tmp)
		writeError(w, http.StatusInternalServerError, "apply: "+err.Error())
		return
	}
	h.audit(r, "update", "backup", 0, map[string]any{"action": "upload_restore", "filename": hdr.Filename})

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{
		"scheduled": true,
		"warnings":  plan.Warnings,
		"message":   "Restore scheduled. Server will restart; reload in ~15s.",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(800 * time.Millisecond)
		os.Exit(0)
	}()
}

// --- /api/config export + import ---

func (h *Handlers) ExportConfig(w http.ResponseWriter, r *http.Request) {
	bundle, err := configio.Export(r.Context(), h.DB, h.NotifRepo, h.ArgosVersion)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export: "+err.Error())
		return
	}
	y, err := configio.MarshalYAML(bundle)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "yaml: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="argos-config-%s.yaml"`,
			time.Now().UTC().Format("20060102")))
	w.Write(y)
}

type importBody struct {
	YAML string `json:"yaml"`
	Mode string `json:"mode"`
}

func (h *Handlers) ValidateImport(w http.ResponseWriter, r *http.Request) {
	yamlBytes, mode, err := readImportRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	bundle, err := configio.Parse(yamlBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	plan, err := configio.Validate(r.Context(), h.DB, h.NotifRepo, bundle, configio.ImportMode(mode))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (h *Handlers) ApplyImport(w http.ResponseWriter, r *http.Request) {
	yamlBytes, mode, err := readImportRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	bundle, err := configio.Parse(yamlBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	// Run validate + apply. Apply is transactional.
	plan, err := configio.Apply(r.Context(), h.DB, bundle, configio.ImportMode(mode))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "apply: "+err.Error())
		return
	}
	h.audit(r, "update", "config_import", 0, map[string]any{"mode": mode, "counts": plan.Counts})
	writeJSON(w, http.StatusOK, plan)
}

// readImportRequest accepts either JSON body {yaml, mode} or
// text/yaml body with ?mode= query, to keep curl calls ergonomic.
func readImportRequest(r *http.Request) ([]byte, string, error) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "merge"
	}
	ct := r.Header.Get("Content-Type")
	if ct == "application/json" || ct == "application/json; charset=utf-8" {
		var body importBody
		if err := decodeJSON(r, &body); err != nil {
			return nil, "", err
		}
		if body.Mode != "" {
			mode = body.Mode
		}
		return []byte(body.YAML), mode, nil
	}
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 10<<20))
	if err != nil {
		return nil, "", err
	}
	return b, mode, nil
}

// --- tiny helper used by chi extraction ---

var _ = chi.URLParam
var _ context.Context
