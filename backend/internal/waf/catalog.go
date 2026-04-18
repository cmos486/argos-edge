package waf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// CRSRule is one entry in the panel's parsed CRS catalog. Consumed by
// /api/crs/rules (and the UI autocomplete in the exclusions modal).
type CRSRule struct {
	ID          int    `json:"id"`
	Paranoia    int    `json:"paranoia"`
	Category    string `json:"category"`
	Description string `json:"description"`
	File        string `json:"file"`
}

var (
	crsIDRe       = regexp.MustCompile(`\bid:(\d+)\b`)
	crsMsgRe      = regexp.MustCompile(`msg:'([^']+)'`)
	crsParanoiaRe = regexp.MustCompile(`paranoia-level/(\d)`)
)

// LoadCRSCatalog parses every .conf under rulesDir and returns the
// catalog sorted by id. Errors opening individual files are logged-
// through (caller decides log level); they don't stop the walk.
func LoadCRSCatalog(rulesDir string) ([]CRSRule, error) {
	if rulesDir == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", rulesDir, err)
	}
	var out []CRSRule
	for _, path := range matches {
		entries, err := parseCRSFile(path)
		if err != nil {
			// Skip unreadable files; caller logs.
			continue
		}
		out = append(out, entries...)
	}
	return out, nil
}

func parseCRSFile(path string) ([]CRSRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	category := categoryFromFilename(filepath.Base(path))
	var out []CRSRule

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var block strings.Builder
	flush := func() {
		text := block.String()
		block.Reset()
		if !strings.Contains(text, "id:") {
			return
		}
		idM := crsIDRe.FindStringSubmatch(text)
		if len(idM) < 2 {
			return
		}
		id, err := strconv.Atoi(idM[1])
		if err != nil {
			return
		}
		// 900000-909999 is CRS setup / initialization / exception
		// scaffolding -- skip from the catalog the UI shows operators.
		// 91xxxx-95xxxx (method, protocol, LFI/RFI, RCE, XSS, SQLi,
		// anomaly scoring, etc.) are the ones the exclusions UI needs.
		if id >= 900000 && id <= 909999 {
			return
		}
		paranoia := 0
		if m := crsParanoiaRe.FindStringSubmatch(text); len(m) > 1 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				paranoia = n
			}
		}
		desc := ""
		if m := crsMsgRe.FindStringSubmatch(text); len(m) > 1 {
			desc = m[1]
		}
		out = append(out, CRSRule{
			ID:          id,
			Paranoia:    paranoia,
			Category:    category,
			Description: desc,
			File:        filepath.Base(path),
		})
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Strip trailing \-continuation marker so we can glue the
		// action list back together into a single buffer for regex.
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, `\`) {
			trimmed = strings.TrimSuffix(trimmed, `\`)
			block.WriteString(trimmed)
			block.WriteByte(' ')
			continue
		}
		block.WriteString(trimmed)
		block.WriteByte(' ')
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			flush()
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// categoryFromFilename turns "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
// into "application-attack-sqli".
func categoryFromFilename(name string) string {
	s := strings.TrimSuffix(name, ".conf")
	parts := strings.SplitN(s, "-", 3)
	if len(parts) < 3 {
		return strings.ToLower(s)
	}
	return strings.ToLower(parts[2])
}
