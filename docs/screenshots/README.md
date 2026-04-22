# Screenshots — capture list

Every image on the docs site. Real captures replace these
placeholders one by one as the operator produces them.

Placeholder behaviour: `placeholder.png` is a 1x1 transparent PNG;
every filename below is a copy of it so `mkdocs build --strict`
passes without broken image references. The alt text on each
`![...]` in the docs already describes what the capture should
show, so the page is still readable without a real image.

When the UI changes meaningfully, the capture goes stale — re-take
and re-commit. Screenshots do NOT carry a version pin; they
represent "how it looks now".

## Capture checklist

Browser: a reasonable zoom (100%). Use the panel in dark mode
(the palette in the stylesheet matches the panel) OR consistently
in light mode — do not mix. Width ~1440 px; crop to the relevant
card rather than a full viewport when a full viewport adds noise.

Files must be committed as actual PNG content (the placeholders
are 68 bytes — a real capture is KiB-MiB). Replace in place; git
history preserves the byte-level before/after.

Navbar caveats:

- The header is a single row with the logo on the left, **status
  pills** (AppSec always; LAN mode when remote) next to the logo,
  and username + logout + hamburger on the right. When a capture
  shows the header, those pills should be visible — they are the
  panel's at-a-glance status surface.
- The twelve top-level routes live inside the hamburger drawer.
  Full-navbar shots should have the drawer CLOSED unless the
  capture specifically illustrates the drawer.

## The list

Landing + getting-started:

- [ ] `dashboard-overview.png` — Dashboard tab, traffic + security
      + world map + health cards visible, any WAF rule hits or
      CrowdSec decisions surfaced realistically.
- [ ] `login.png` — Login page with the username + password form.
      If OIDC is configured in the capture env, the **Sign in with
      SSO** button should also appear.
- [ ] `totp-setup.png` — System → Two-factor authentication →
      enrollment dialog with the QR code + readable secret string
      + the list of 10 recovery codes.
- [ ] `target-group-first-target.png` — Target Group detail page
      with ONE target visible at a LAN address (e.g.
      10.0.0.42:8080).

Workflows:

- [ ] `target-group-form.png` — Target Group creation form with
      name / protocol / verify_tls / algorithm / health-check
      fields all visible.
- [ ] `target-group-two-targets.png` — Same detail page with TWO
      targets (for the multi-target LB example).
- [ ] `host-form.png` — Host creation form with domain +
      target group selector + TLS mode + TLS email + enabled
      toggle.
- [ ] `appsec-metrics.png` — AppSec tab → Metrics sub-tab with
      hits per rule + severity distribution (capture in a window
      that has real WAF data).
- [ ] `hosts-list-auth-column.png` — Hosts list with the
      auth_required column visible on at least one row.
- [ ] `dashboard-security.png` — Dashboard → Security section
      specifically (world map + top IPs table in the same
      screenshot).
- [ ] `sso-allowlist.png` — System → SSO panel focused on the
      Allowed emails textarea with at least one entry visible.
- [ ] `backups-list.png` — Backups tab with a mix of scheduled
      and manual backups in the list.

Features:

- [ ] `threats-decisions.png` — Threats tab with the decision
      list including IP, scenario, duration, origin columns.
- [ ] `appsec-status.png` — AppSec tab → Status sub-tab with
      the mode selector + rules table.
- [ ] `notifications-deliveries.png` — Notifications →
      Deliveries tab with a mix of sent / failed / rate_limited.
- [ ] `backup-settings.png` — System Settings → Backup section
      with enabled toggle + cron expression + retention days.
- [ ] `geoip-status.png` — System → GeoIP tab with country + ASN
      DB versions + last refresh timestamp + Refresh button.
- [ ] `security-overview.png` — Security tab with KPI cards +
      per-domain table. Capture full viewport.
- [ ] `logs-browser.png` — Logs tab with filters + results table
      populated. Capture with 1h range selected.
- [ ] `settings-panel.png` — Settings tab with both Security and
      Logs sections visible. Capture vertical layout.
- [x] `settings-dns-providers.png` — Settings → DNS providers
      section, both cards (Cloudflare + Route 53) visible with at
      least one in the Configured state (green badge). v1.3.0-beta.
- [x] `host-form-dns-provider-dropdown.png` — Host form with
      TLS mode=auto + DNS-01 selected, showing the provider
      dropdown below the challenge radios. Capture with both
      Cloudflare and Route 53 enabled so the dropdown is populated.
      v1.3.0-beta.

## Replacement procedure

```bash
# Take the capture. Save as PNG.
# Resize to <1600 px width if larger.
# Replace in place.
cp ~/Downloads/dashboard-overview.png docs/screenshots/dashboard-overview.png

# Verify the portal still builds.
mkdocs build --strict

# Commit with a scoped message.
git add docs/screenshots/dashboard-overview.png
git commit -m "docs(screenshots): refresh dashboard-overview"
```

## When in doubt

- Prefer cropped / focused screenshots over full-viewport unless
  the full viewport is the message.
- Redact or substitute any real secrets (OIDC client IDs, tenant
  domains, LAN IPs of private services). Prefer example.com /
  10.0.0.x placeholders.
- Keep file size under 500 KB. If a PNG is larger, compress with
  pngquant or oxipng before committing.
