package geoip

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Downloader fetches the monthly DB-IP Lite CSVs-as-mmdb. DB-IP
// publishes on the 1st of each month at
// https://download.db-ip.com/free/dbip-(country|asn)-lite-YYYY-MM.mmdb.gz.
// We download, gunzip to a .new path, validate by opening it, and
// rename atomically.
type Downloader struct {
	DB     *DB
	Client *http.Client
	// URL templates -- exported so tests can override with a fixture server.
	CountryURL string // must contain %s for YYYY-MM
	ASNURL     string
}

const (
	countryTmpl = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"
	asnTmpl     = "https://download.db-ip.com/free/dbip-asn-lite-%s.mmdb.gz"
)

// NewDownloader returns a downloader with the default DB-IP URLs
// and a 5-minute HTTP client. The mmdb.gz files run ~5 MiB so the
// generous timeout handles slow homelab uplinks.
func NewDownloader(db *DB) *Downloader {
	return &Downloader{
		DB:         db,
		Client:     &http.Client{Timeout: 5 * time.Minute},
		CountryURL: countryTmpl,
		ASNURL:     asnTmpl,
	}
}

// RefreshAll pulls the current-month country + ASN databases,
// atomically swaps them into the DB, and records telemetry on the
// wrapping DB. Returns the first error encountered. If country OK
// and ASN fails (or vice versa), the successful one IS installed --
// partial failures are better than none for phase-1 UX.
func (dl *Downloader) RefreshAll(ctx context.Context) error {
	ym := time.Now().UTC().Format("2006-01")
	countryErr := dl.refreshOne(ctx, ym, "country", dl.DB.CountryPath(), dl.CountryURL)
	asnErr := dl.refreshOne(ctx, ym, "asn", dl.DB.ASNPath(), dl.ASNURL)

	// After at least one success, reload into the live DB.
	if countryErr == nil || asnErr == nil {
		if err := dl.DB.Load(); err != nil {
			if countryErr == nil {
				countryErr = fmt.Errorf("reload: %w", err)
			}
		}
	}
	var finalErr error
	switch {
	case countryErr != nil && asnErr != nil:
		finalErr = fmt.Errorf("country: %v; asn: %v", countryErr, asnErr)
	case countryErr != nil:
		finalErr = fmt.Errorf("country: %w", countryErr)
	case asnErr != nil:
		finalErr = fmt.Errorf("asn: %w", asnErr)
	}
	dl.DB.recordRefresh(finalErr)
	return finalErr
}

// refreshOne handles one of the two files. Steps:
//  1. HTTP GET the .gz to a pipe
//  2. Stream gunzip into /data/geoip/<name>.mmdb.new
//  3. Validate by opening it with maxminddb.Open
//  4. Rename over the live path
//
// Atomic on the same filesystem (argos_data is a single volume).
func (dl *Downloader) refreshOne(ctx context.Context, ym, kind, finalPath, urlTmpl string) error {
	url := fmt.Sprintf(urlTmpl, ym)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := dl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d on %s", resp.StatusCode, url)
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := finalPath + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("gzip header: %w", err)
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	// Validate: must open + have a sane metadata block before we
	// trust this file on the live path.
	reader, err := maxminddb.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("validate %s: %w", kind, err)
	}
	_ = reader.Close()
	if err := os.Rename(tmp, finalPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
