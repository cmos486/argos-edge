package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/certs"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// maxManualCertBody caps each uploaded PEM blob at 64 KiB. A realistic
// cert + key pair is < 8 KiB; this leaves room for a full chain up to
// ~6 intermediates without letting an operator DoS the handler with
// a huge upload.
const maxManualCertBody = 64 << 10

// maxManualCertTotal caps the whole multipart request at 256 KiB.
const maxManualCertTotal = 256 << 10

// manualCertResponse is the JSON projection of a host_manual_certs
// row for GET endpoints. Never includes the encrypted key blob: the
// server is the only consumer that ever needs it.
type manualCertResponse struct {
	HostID            int64     `json:"host_id"`
	Domain            string    `json:"domain"`
	Issuer            string    `json:"issuer,omitempty"`
	SubjectCommonName string    `json:"subject_cn,omitempty"`
	SANs              []string  `json:"sans"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysLeft          int       `json:"days_left"`
	Status            string    `json:"status"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	UploadedAt        time.Time `json:"uploaded_at"`
	UploadedBy        int64     `json:"uploaded_by"`
	HasChain          bool      `json:"has_chain"`
}

// ListManualCerts GET /api/manual-certs
func (h *Handlers) ListManualCerts(w http.ResponseWriter, r *http.Request) {
	items, err := db.ListManualCerts(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list manual certs failed")
		return
	}
	out := make([]manualCertResponse, 0, len(items))
	now := time.Now().UTC()
	for _, it := range items {
		out = append(out, manualCertRowToResp(it.ManualCertRow, it.Domain, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetManualCert GET /api/manual-certs/{id}
func (h *Handlers) GetManualCert(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	row, err := db.GetManualCertByHostID(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrManualCertNotFound) {
			writeError(w, http.StatusNotFound, "no manual cert for this host")
			return
		}
		writeError(w, http.StatusInternalServerError, "get manual cert failed")
		return
	}
	writeJSON(w, http.StatusOK, manualCertRowToResp(row, host.Domain, time.Now().UTC()))
}

// UploadManualCert POST /api/manual-certs/{id} accepts a multipart
// form with fields cert_pem, key_pem, chain_pem (optional) plus an
// optional "confirm_replace=true" field. On success the cert is
// validated, the key is encrypted, the DB row is upserted, the files
// are written to the shared volume, and the host row flips to
// tls_mode=manual triggering a Caddy reconcile.
func (h *Handlers) UploadManualCert(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "cipher not wired")
		return
	}
	if h.ManualCertStore == nil {
		writeError(w, http.StatusServiceUnavailable, "manual cert store not wired")
		return
	}

	// Size cap before parsing so a 1 GiB body does not get buffered.
	r.Body = http.MaxBytesReader(w, r.Body, maxManualCertTotal)
	if err := r.ParseMultipartForm(maxManualCertTotal); err != nil {
		writeError(w, http.StatusBadRequest, "parse multipart: "+err.Error())
		return
	}

	certPEM, err := readPartString(r, "cert_pem")
	if err != nil {
		writeError(w, http.StatusBadRequest, "cert_pem: "+err.Error())
		return
	}
	keyPEM, err := readPartString(r, "key_pem")
	if err != nil {
		writeError(w, http.StatusBadRequest, "key_pem: "+err.Error())
		return
	}
	chainPEM, _ := readPartString(r, "chain_pem")

	validated, err := certs.ValidateManualCert(certPEM, keyPEM, chainPEM, host.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	encKey, err := h.Cipher.Encrypt(validated.KeyPEM)
	if err != nil {
		slog.Error("manual cert: encrypt key", "host", host.Domain, "error", err)
		writeError(w, http.StatusInternalServerError, "encrypt failed")
		return
	}

	sansJSON, err := certs.SANsJSON(validated.SANs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal sans: "+err.Error())
		return
	}

	var uploadedBy int64
	if u, ok := userFromContext(r.Context()); ok {
		uploadedBy = u.ID
	}
	if _, err := db.UpsertManualCert(r.Context(), h.DB, db.UpsertManualCertInput{
		HostID:            host.ID,
		CertPEM:           validated.CertPEM,
		KeyPEMEncrypted:   []byte(encKey),
		ChainPEM:          validated.ChainPEM,
		NotAfter:          validated.NotAfter,
		NotBefore:         validated.NotBefore,
		SANs:              sansJSON,
		FingerprintSHA256: validated.Fingerprint,
		UploadedBy:        uploadedBy,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "db upsert: "+err.Error())
		return
	}

	if err := h.ManualCertStore.Write(host.ID, validated); err != nil {
		slog.Error("manual cert: write files", "host", host.Domain, "error", err)
		// DB row is already in place; files missing means Caddy will
		// refuse to load. Surface the error; operator retries.
		writeError(w, http.StatusInternalServerError, "write files: "+err.Error())
		return
	}

	// Flip tls_mode to manual + clear ACME-related fields. Reconcile
	// runs on the next HostsToCaddyConfig.
	updated, err := flipHostToManual(r.Context(), h, host)
	if err != nil {
		slog.Error("manual cert: flip tls_mode", "host", host.Domain, "error", err)
		writeError(w, http.StatusInternalServerError, "update host: "+err.Error())
		return
	}

	h.audit(r, "upload", "manual_cert", host.ID, map[string]any{
		"domain":      host.Domain,
		"fingerprint": validated.Fingerprint,
		"not_after":   validated.NotAfter,
		"warnings":    validated.Warnings,
	})
	h.reconcile(r.Context())

	resp := manualCertRowToResp(db.ManualCertRow{
		HostID:            host.ID,
		CertPEM:           validated.CertPEM,
		ChainPEM:          validated.ChainPEM,
		NotAfter:          validated.NotAfter,
		NotBefore:         validated.NotBefore,
		SANs:              sansJSON,
		FingerprintSHA256: validated.Fingerprint,
		UploadedAt:        time.Now().UTC(),
		UploadedBy:        uploadedBy,
	}, host.Domain, time.Now().UTC())
	// Wrap the response with any validation warnings so the UI can
	// render them without a second round-trip.
	writeJSON(w, http.StatusOK, map[string]any{
		"cert":     resp,
		"warnings": validated.Warnings,
		"host":     updated,
	})
}

// DeleteManualCert DELETE /api/manual-certs/{id}?revert=auto|none
// Removes the DB row, deletes the files, flips the host's tls_mode
// to the requested value (default 'auto').
func (h *Handlers) DeleteManualCert(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	revert := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("revert")))
	if revert == "" {
		revert = string(models.TLSModeAuto)
	}
	if revert != string(models.TLSModeAuto) && revert != string(models.TLSModeNone) {
		writeError(w, http.StatusBadRequest, `revert must be "auto" or "none"`)
		return
	}

	if err := db.DeleteManualCert(r.Context(), h.DB, host.ID); err != nil {
		if errors.Is(err, db.ErrManualCertNotFound) {
			writeError(w, http.StatusNotFound, "no manual cert for this host")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete: "+err.Error())
		return
	}
	if h.ManualCertStore != nil {
		if err := h.ManualCertStore.Remove(host.ID); err != nil {
			slog.Warn("manual cert: remove files", "host", host.Domain, "error", err)
			// continue; DB row is gone which is the source of truth
		}
	}
	host.TLSMode = models.TLSMode(revert)
	updated, err := db.UpdateHost(r.Context(), h.DB, host)
	if err != nil {
		slog.Error("manual cert: revert tls_mode", "host", host.Domain, "error", err)
		writeError(w, http.StatusInternalServerError, "update host: "+err.Error())
		return
	}
	h.audit(r, "delete", "manual_cert", host.ID, map[string]any{
		"domain":      host.Domain,
		"revert_mode": revert,
	})
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": updated})
}

// DownloadManualCert GET /api/manual-certs/{id}/download streams the
// stored cert+chain PEM for inspection. Key is NEVER served.
func (h *Handlers) DownloadManualCert(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	row, err := db.GetManualCertByHostID(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrManualCertNotFound) {
			writeError(w, http.StatusNotFound, "no manual cert")
			return
		}
		writeError(w, http.StatusInternalServerError, "get: "+err.Error())
		return
	}
	out := row.CertPEM
	if row.ChainPEM != "" {
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += row.ChainPEM
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="manual-cert-%d.pem"`, id))
	_, _ = w.Write([]byte(out))
}

// manualCertRowToResp builds the JSON projection. Computes days_left
// and status from not_after so the UI renders badges with the same
// thresholds as /certs.
func manualCertRowToResp(r db.ManualCertRow, domain string, now time.Time) manualCertResponse {
	sans := []string{}
	if r.SANs != "" {
		_ = json.Unmarshal([]byte(r.SANs), &sans)
	}
	left := int(r.NotAfter.Sub(now).Hours() / 24)
	status := classifyCertStatus(left)
	return manualCertResponse{
		HostID:            r.HostID,
		Domain:            domain,
		SANs:              sans,
		NotBefore:         r.NotBefore.UTC(),
		NotAfter:          r.NotAfter.UTC(),
		DaysLeft:          left,
		Status:            status,
		FingerprintSHA256: r.FingerprintSHA256,
		UploadedAt:        r.UploadedAt.UTC(),
		UploadedBy:        r.UploadedBy,
		HasChain:          r.ChainPEM != "",
	}
}

// flipHostToManual updates the host so its tls_mode=manual and writes
// it back through the same code path the public UpdateHost handler
// uses. Returns the re-read host so the caller can echo it.
func flipHostToManual(ctx context.Context, h *Handlers, host models.Host) (models.Host, error) {
	host.TLSMode = models.TLSModeManual
	return db.UpdateHost(ctx, h.DB, host)
}

// readPartString pulls one form field out of an already-parsed
// multipart request as a trimmed string. Enforces maxManualCertBody
// on each individual field.
func readPartString(r *http.Request, name string) (string, error) {
	// Strings sent as form fields (not files) land in r.MultipartForm.Value.
	if r.MultipartForm != nil {
		if vs, ok := r.MultipartForm.Value[name]; ok && len(vs) > 0 {
			return strings.TrimSpace(vs[0]), nil
		}
	}
	// Files land in r.MultipartForm.File. Most UIs upload PEMs as files.
	f, _, err := r.FormFile(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	limited := io.LimitReader(f, maxManualCertBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(data) > maxManualCertBody {
		return "", fmt.Errorf("field exceeds %d bytes", maxManualCertBody)
	}
	return strings.TrimSpace(string(data)), nil
}
