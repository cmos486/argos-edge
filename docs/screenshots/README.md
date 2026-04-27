# Screenshots — capture list

Operational guide for the screenshots that ship with the docs
portal. Synced post-v1.3.35: the demo environment scaffold
(`scripts/demo/init.sh`) is now the canonical capture environment,
so this file lists what to capture and tells you exactly how to
land each one against `localhost:9181`.

The portal already references every filename below; replacing a
`[ ]` entry is a one-byte-to-MiB change tracked by git.

## Capture environment

Use the v1.3.35 demo stack — it's purpose-built for this:

```bash
cd ~/argos-edge
scripts/demo/init.sh
# panel ready at http://localhost:9181  login: demo / demo1234
```

The demo seeds 8 hosts, 5 country bans, 4 whitelist entries, 10
banned IPs in CrowdSec LAPI, 3 notification channels, AppSec
tuning + drift state — every panel surface shows populated rows
instead of a fresh-install zero state. All seeded data is RFC
5737 IP space + `*.example.{com,org,net}` hostnames + `demo:`-
prefixed names, so screenshots can land in the public docs portal
without sanitization gymnastics.

When you're done capturing:

```bash
scripts/demo/teardown.sh --purge   # full cleanup
```

See `docs/operations/demo-environment.md` for the full
non-interference contract (zero impact on argos-prod).

### Browser settings

- **Width**: ~1440 px viewport. Crop to the relevant card rather
  than full viewport when full viewport adds noise.
- **Theme**: dark mode (the panel's slate palette matches the
  docs portal's dark theme). Pick one and stay consistent across
  the batch — don't mix light/dark in one release.
- **Zoom**: 100%. Anything else makes the rendered text not match
  the live panel.
- **Format**: PNG. Compress with `pngquant` or `oxipng` if
  >500 KiB. JPEG only for full-viewport shots if PNG bloats.

### Navbar caveats

- The header is one row: logo on the left, **status pills**
  (AppSec always; LAN mode when remote; **v1.3.35 version pill**)
  next to the logo, username + logout + hamburger on the right.
  Captures that include the header should show those pills —
  they're the panel's at-a-glance status surface.
- The twelve top-level routes live inside the hamburger drawer.
  Full-navbar shots should have the drawer **closed** unless the
  capture specifically illustrates the drawer.

## Naming convention

```
docs/screenshots/<area>-<surface>.png
```

- Lowercase, hyphenated, single tier (no subdirectories).
- `<area>` = top-level surface group: `dashboard`, `hosts`,
  `security`, `appsec`, `drift`, `country-bans`, `system`, etc.
- `<surface>` = the specific tab / modal / element.

Examples: `security-banned.png`, `host-form-true-detect.png`,
`country-bans-progress.png`.

## Status legend

| Mark | Meaning |
|---|---|
| `[x]` | Real capture committed; up-to-date with current UI. |
| `[~]` | Real capture committed, but UI has shifted — RETAKE on next session. |
| `[ ]` | Pending: file may or may not exist, needs a real capture. |

## Inventory

### Landing + getting-started

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `dashboard-overview.png` | `index.md`, `getting-started/first-run.md`, `features/observability.md` | `[~]` | Pre-v1.3.20 capture; retake to surface the v1.3.35 header pill. |
| `login.png` | `getting-started/first-run.md` | `[x]` | Login form with username + password (+ SSO button when configured). |
| `totp-setup.png` | `getting-started/first-run.md`, `features/auth-local.md` | `[x]` | TOTP enrollment dialog with QR + readable secret + 10 recovery codes. |

### Hosts + target groups

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `target-group-form.png` | `workflows/add-host.md` | `[x]` | TG creation form (name / protocol / verify_tls / algorithm / health-check). |
| `target-group-first-target.png` | `getting-started/quickstart.md` | `[x]` | TG detail page with one target. |
| `target-group-two-targets.png` | `workflows/add-host.md` | `[x]` | TG detail page with two targets. |
| `host-form.png` | `workflows/add-host.md` | `[~]` | RETAKE — modal layout shifted post-v1.3.29 (`true_detect_mode` checkbox added). |
| `host-form-true-detect.png` | TODO embed in `features/crowdsec.md` AppSec section | `[ ]` | NEW — Host edit modal scrolled to the **AppSec** section showing the `true_detect_mode` checkbox checked. v1.3.29. |
| `hosts-list-auth-column.png` | `workflows/publish-with-sso.md` | `[x]` | Hosts list with the `auth_required` column visible. |
| `hosts-detect-badge.png` | TODO embed in `features/crowdsec.md` | `[ ]` | NEW — Hosts list row with the **DETECT** badge next to a host that has `true_detect_mode=true` (admin / grafana / vault in the demo seed). v1.3.29. |
| `host-form-dns-provider-dropdown.png` | `features/dns-providers.md`, `release-notes/v1.3.0.md`, `release-notes/v1.3.1.md` | `[x]` | Host form with DNS-01 challenge + provider dropdown. |

### Security tab

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `security-overview.png` | `features/security-overview.md` | `[x]` | Security tab KPI cards + per-domain table. |
| `security-banned.png` | TODO embed in `features/crowdsec.md` | `[ ]` | NEW — Banned IPs tab (10 RFC5737 IPs from the demo LAPI seed; mix of CAPI + cscli + AppSec WAF origins). v1.3.20. |
| `security-whitelist.png` | TODO embed in `features/security-overview.md` | `[ ]` | NEW — Whitelist tab (4 entries with `demo:` reasons). v1.3.20. |
| `security-activity.png` | TODO embed in `features/security-overview.md` | `[ ]` | NEW — Activity audit log (15 entries spanning 7 days). v1.3.20. |
| `security-scenarios.png` | TODO embed in `features/crowdsec.md` Scenarios section | `[ ]` | NEW — Scenarios tab; **hover one row** so the description tooltip (ⓘ glyph) is visible. v1.3.30. |

### AppSec + drift

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `appsec-status.png` | `features/waf.md` | `[~]` | RETAKE — current capture is the pre-v1.3.25 tuning UI shape; redo against the new `/security/appsec` page with threshold sliders. |
| `appsec-metrics.png` | `workflows/add-host.md` | `[x]` | AppSec → Metrics sub-tab (hits per rule + severity distribution). |
| `drift-indicators.png` | TODO embed in `features/drift-detection.md` | `[ ]` | NEW — Top-of-page amber **drift banner** + per-tab amber dots on Scenarios + AppSec tabs. The demo seed sets `drift_state.drift_detected=true` so this renders without manual setup. v1.3.27. |

### Country bans

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `country-bans-progress.png` | TODO embed in `features/country-bans.md` | `[ ]` | NEW — Settings → Country bans section. Capture mid-expansion: the demo seed has 5 countries already done (BR/CN/KR/RU/IR); manually trigger a 6th (e.g. `JP`) to capture the async-progress bar with `chunks_done / chunks_total` updating. v1.3.31. |

### Self-block

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `selfblock-banner.png` | TODO embed in `features/security-overview.md` | `[ ]` | NEW — SelfBlockBanner v2 visible at the top of any panel page when the operator's IP is in a CrowdSec ban. **NOT auto-seeded by the demo** (would require knowing the operator's IP). To capture: in the demo, ban `127.0.0.1` via `cscli decisions add --ip 127.0.0.1 --reason "demo: self-block"` and reload the panel. v1.3.20. |

### Threats (legacy)

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `threats-decisions.png` | `features/crowdsec.md` | `[~]` | RETAKE — captured against the legacy `/threats` URL retired in v1.3.24. The current home for this content is `/security/banned` — overlaps with `security-banned.png` above. Consider deleting this file + repointing the embed in `features/crowdsec.md` once `security-banned.png` lands. |

### Notifications

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `notifications-deliveries.png` | `features/notifications.md` | `[x]` | Deliveries tab with status filters + recent attempts list. |

### System + settings

| Path | Embedded in | Status | Notes |
|---|---|---|---|
| `dashboard-security.png` | `workflows/respond-to-attack.md` | `[x]` | Dashboard → Security section (world map + top IPs). |
| `geoip-status.png` | `features/observability.md` | `[x]` | System → GeoIP tab. |
| `logs-browser.png` | `features/logs-browser.md` | `[x]` | Logs tab with 1h range + populated table. |
| `settings-panel.png` | `features/settings.md` | `[x]` | Settings tab vertical layout (Security + Logs sections). |
| `settings-dns-providers.png` | `features/dns-providers.md`, release notes | `[x]` | DNS providers section. v1.3.0-beta. |
| `sso-allowlist.png` | `workflows/onboard-admin.md` | `[x]` | System → SSO allowed-emails textarea. |
| `backup-settings.png` | `features/backups.md` | `[x]` | System Settings → Backup section. |
| `backups-list.png` | `workflows/restore-backup.md` | `[x]` | Backups tab with mixed scheduled + manual entries. |

## Capture session workflow

End-to-end for a "post-v1.3.35 captures" commit:

```bash
cd ~/argos-edge

# 1. Bring up the populated demo stack (zero impact on argos-prod).
scripts/demo/init.sh

# 2. Open http://localhost:9181 in a fresh browser window.
#    Log in as demo / demo1234. Pick dark mode.

# 3. For each [ ] / [~] entry above, navigate per "Notes" and
#    capture. Save under docs/screenshots/<filename>.png. PNG
#    only; oxipng or pngquant if >500 KiB.

# 4. Verify the docs portal still builds with the new images.
mkdocs build --strict

# 5. Verify no operator-specific data leaked into the captures
#    (the demo seed uses only RFC 5737 + example.* but a stray
#    LAN URL in a tooltip could still slip in).
./scripts/check-no-personal-data.sh

# 6. Commit. One commit per release, even if multiple files.
git add docs/screenshots/*.png
git commit -m "docs(screenshots): post-v1.3.35 captures"

# 7. Tear down the demo stack.
scripts/demo/teardown.sh --purge
```

For each newly-captured `[ ]` entry, also flip the entry's TODO
embed reference into a real `![...]` in the listed feature doc.
That part is a separate doc-only commit; keep it scoped to the
release notes the screenshots ship under.

## Maintenance

When a new feature ships with a UI surface:

1. Add an entry to the inventory table above with status `[ ]`.
2. Capture during the release's screenshot session (or note the
   defer in the release notes).
3. Add the `![...]` embed in the feature doc.

When a UI surface gets redesigned:

1. Flip existing entry's status from `[x]` to `[~]`.
2. Add a one-line "Notes" entry explaining what shifted.
3. Schedule the retake against the next release that touches the
   feature.

Periodic refresh: every 2-3 doc releases, eyeball the inventory
against the live panel. The `[~]` markers exist precisely for
this — UI drift is normal, the README is the place that catches it.

## Replacement procedure

```bash
# Take the capture. Save as PNG. Resize to <1600 px width if larger.
cp ~/Downloads/security-banned.png docs/screenshots/security-banned.png

# Verify the portal still builds.
mkdocs build --strict

# Commit with a scoped message.
git add docs/screenshots/security-banned.png
git commit -m "docs(screenshots): add security-banned (v1.3.20)"
```

## When in doubt

- Prefer cropped / focused screenshots over full-viewport unless
  the full viewport is the message.
- Demo seed data is RFC 5737 / `example.*` / `demo:`-prefixed —
  safe to ship as-is. If a screenshot picked up anything else (a
  stray LAN IP, a real operator domain), redact or recapture
  against a fresh `init.sh` run.
- Keep file size under 500 KiB. If a PNG is larger, compress with
  `pngquant` or `oxipng` before committing.
