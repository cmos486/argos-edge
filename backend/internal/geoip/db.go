package geoip

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// DB holds the two maxminddb readers (country + ASN) and performs
// atomic swaps on refresh. Readers are stored behind a RWMutex so
// Lookup() can read concurrently without contending with a refresh.
// After swapping in the new reader, the old one is closed after a
// small delay so in-flight requests holding a pointer don't crash.
type DB struct {
	Dir string // /data/geoip

	mu      sync.RWMutex
	country *maxminddb.Reader
	asn     *maxminddb.Reader

	// version strings lifted from maxminddb metadata. Derived at load
	// time as "2026-04" from the "BuildEpoch".
	countryVersion string
	asnVersion     string
	loadedAt       time.Time

	// refresh telemetry exposed via /api/geoip/status
	lastRefreshAt    atomic.Int64 // unix nanos; 0 = never
	lastRefreshError atomic.Pointer[string]
}

// NewDB constructs a DB bound to the given directory. The readers
// stay nil until Load() runs.
func NewDB(dir string) *DB {
	return &DB{Dir: dir}
}

// CountryPath and ASNPath are the canonical filenames on disk. The
// downloader writes .new variants, validates them, and renames.
func (d *DB) CountryPath() string { return filepath.Join(d.Dir, "country.mmdb") }
func (d *DB) ASNPath() string     { return filepath.Join(d.Dir, "asn.mmdb") }

// Load opens both .mmdb files if present. Missing files are NOT
// fatal -- the startup path kicks off a background download and
// Lookup() returns Unknown results in the meantime.
func (d *DB) Load() error {
	country, cErr := openIfExists(d.CountryPath())
	asn, aErr := openIfExists(d.ASNPath())
	if cErr != nil && aErr != nil {
		return fmt.Errorf("both dbs failed: country=%v, asn=%v", cErr, aErr)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.country = country
	d.asn = asn
	d.countryVersion = readVersion(country)
	d.asnVersion = readVersion(asn)
	d.loadedAt = time.Now().UTC()
	return nil
}

// Status is the snapshot exposed via /api/geoip/status.
type Status struct {
	CountryDBVersion string    `json:"country_db_version"`
	ASNDBVersion     string    `json:"asn_db_version"`
	LoadedAt         time.Time `json:"loaded_at"`
	LastRefreshAt    time.Time `json:"last_refresh_at"`
	LastRefreshError string    `json:"last_refresh_error"`
	CountryDBPath    string    `json:"country_db_path"`
	ASNDBPath        string    `json:"asn_db_path"`
	CountryDBSize    int64     `json:"country_db_size_bytes"`
	ASNDBSize        int64     `json:"asn_db_size_bytes"`
	Attribution      string    `json:"attribution"`
}

// Status returns a thread-safe snapshot. Never errors; missing fields
// come back as zero values.
func (d *DB) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	st := Status{
		CountryDBVersion: d.countryVersion,
		ASNDBVersion:     d.asnVersion,
		LoadedAt:         d.loadedAt,
		CountryDBPath:    d.CountryPath(),
		ASNDBPath:        d.ASNPath(),
		Attribution:      AttributionText,
	}
	if fi, err := os.Stat(d.CountryPath()); err == nil {
		st.CountryDBSize = fi.Size()
	}
	if fi, err := os.Stat(d.ASNPath()); err == nil {
		st.ASNDBSize = fi.Size()
	}
	if ns := d.lastRefreshAt.Load(); ns > 0 {
		st.LastRefreshAt = time.Unix(0, ns).UTC()
	}
	if p := d.lastRefreshError.Load(); p != nil {
		st.LastRefreshError = *p
	}
	return st
}

// recordRefresh stamps the telemetry counters after a refresh cycle.
// err is stored verbatim (empty string for success).
func (d *DB) recordRefresh(err error) {
	d.lastRefreshAt.Store(time.Now().UTC().UnixNano())
	if err == nil {
		empty := ""
		d.lastRefreshError.Store(&empty)
		slog.Info("geoip: refresh ok",
			"country_version", d.countryVersion,
			"asn_version", d.asnVersion)
	} else {
		msg := err.Error()
		d.lastRefreshError.Store(&msg)
		slog.Warn("geoip: refresh failed", "error", err)
	}
}

// openIfExists opens the file if it is present on disk; missing is
// not an error (returned nil, nil). An unreadable or malformed file
// returns the underlying error so the startup path can log it.
func openIfExists(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return maxminddb.Open(path)
}

// readVersion produces a short "YYYY-MM" string from the mmdb
// BuildEpoch metadata. Empty when the reader is nil.
func readVersion(r *maxminddb.Reader) string {
	if r == nil {
		return ""
	}
	t := time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC()
	return t.Format("2006-01")
}
