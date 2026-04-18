package waf

import (
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// BuildDirectives renders the Coraza directive text for a single host.
// The output is the `directives` field inside the coraza_waf handler's
// JSON config. Order matters:
//
//  1. Include /etc/coraza/coraza.conf     -- panel base settings
//  2. Include /etc/coraza/crs-setup.conf  -- CRS knobs
//  3. SecAction paranoia override         -- per-host level
//  4. SecRuleRemoveById <id>              -- global exclusions
//  5. SecRule ... ctl:ruleRemoveById=<id> -- path-scoped exclusions
//  6. Include /etc/coraza/crs/rules/*.conf -- the CRS itself
//  7. <custom SecRule text>               -- operator extensions
//  8. SecRuleEngine On / DetectionOnly    -- mode, last wins
//
// Disabled exclusions and disabled custom rules are omitted.
func BuildDirectives(bundle models.HostSecurityBundle) string {
	var b strings.Builder

	b.WriteString("Include /etc/coraza/coraza.conf\n")
	b.WriteString("Include /etc/coraza/crs-setup.conf\n")

	paranoia := bundle.WAFParanoia
	if paranoia < 1 || paranoia > 4 {
		paranoia = 1
	}
	fmt.Fprintf(&b,
		"SecAction \"id:9000001,phase:1,pass,nolog,"+
			"setvar:tx.blocking_paranoia_level=%d,"+
			"setvar:tx.detection_paranoia_level=%d\"\n",
		paranoia, paranoia)

	// Panel-reserved tx id range starts at 9,100,000 for
	// path-scoped exclusions so we never collide with CRS (900xxx,
	// 9xxxxx internal) or user rules (100000-899999).
	txID := int64(9100000)
	for _, ex := range bundle.Exclusions {
		if !ex.Enabled {
			continue
		}
		if ex.PathPattern == "" {
			fmt.Fprintf(&b, "SecRuleRemoveById %d\n", ex.CRSRuleID)
			continue
		}
		fmt.Fprintf(&b,
			"SecRule REQUEST_URI \"@beginsWith %s\" "+
				"\"id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%d\"\n",
			escapeForSecRule(ex.PathPattern), txID, ex.CRSRuleID)
		txID++
	}

	b.WriteString("Include /etc/coraza/crs/rules/*.conf\n")

	for _, cr := range bundle.CustomRules {
		if !cr.Enabled {
			continue
		}
		b.WriteString(strings.TrimRight(cr.SecRule, "\n"))
		b.WriteByte('\n')
	}

	if bundle.WAFMode == models.WAFModeBlock {
		b.WriteString("SecRuleEngine On\n")
	} else {
		b.WriteString("SecRuleEngine DetectionOnly\n")
	}
	return b.String()
}

// escapeForSecRule escapes quotes so a path containing " does not break
// the enclosing SecRule argument list. Homelab inputs are tame but the
// panel still validates domain / path elsewhere; this is defense in depth.
func escapeForSecRule(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
