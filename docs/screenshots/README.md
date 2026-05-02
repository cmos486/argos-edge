# Screenshots — capture list

Operational guide for the screenshots that ship with the docs
portal. v1.3.35.5 restructured the inventory to use explicit
fields per entry (Route / How to reach / What to see / Crop /
Status / Embedded in) and reordered everything by hamburger
drawer route, with a Setup recipes section at the end for the
state-changing prerequisites that several captures need.

The portal already references every filename below; replacing a
`[ ]` entry is a one-byte-to-MiB change tracked by git.

## Capture environment

Use the v1.3.35 demo stack — it's purpose-built for this:

```bash
cd ~/argos-edge
scripts/demo/init.sh
# panel ready at http://localhost:9181  login: demo / demo1234
```

The demo seeds 14 hosts, 8 country bans, 8 whitelist entries, 100
banned IPs in CrowdSec LAPI, 5 notification channels, AppSec
tuning + drift state, and more — every panel surface shows
populated rows instead of a fresh-install zero state. All seeded
data is RFC 5737 IP space + `*.example.{com,org,net}` hostnames
+ `demo:`-prefixed names, so screenshots can land in the public
docs portal without sanitization gymnastics.

When you're done capturing:

```bash
scripts/demo/teardown.sh --purge   # full cleanup
```

See `docs/operations/demo-environment.md` for the full
non-interference contract (zero impact on argos-prod).

> If you capture against a productive instance instead of the
> demo stack, the resulting PNGs are NOT safe for public docs
> without manual review before commit. Real domains, real LAN
> IPs, real operator usernames will leak. Default to the demo;
> only deviate when a specific surface can't be reproduced
> there.

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
  (AppSec always; LAN mode when remote; **version pill**)
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

Ordered by hamburger drawer (top of nav → bottom), then
sub-views/modals as children of each route, with the Country
bans sub-section under Settings and a Setup recipes section at
the end.

### 1. Auth

#### `login.png` `[x]`

- **Route**: `/login`
- **How to reach**: open the panel before logging in (or click
  Logout from anywhere).
- **What to see**: username + password form. If OIDC is
  configured in the capture env, a **Sign in with SSO** button
  also appears.
- **Crop**: form card centered.
- **Embedded in**: `getting-started/first-run.md`

#### `totp-setup.png` `[x]`

- **Route**: `/system` → Two-factor authentication
- **How to reach**: log in → click `System` in the hamburger →
  Two-factor → Enable TOTP. ⚠ Changes state: enables 2FA on the
  current user; revert by Disable TOTP.
- **What to see**: enrollment dialog with QR code, readable
  secret string, and the list of 10 recovery codes.
- **Crop**: dialog, including all 10 recovery codes.
- **Embedded in**: `getting-started/first-run.md`,
  `features/auth-local.md`

### 2. Dashboard

#### `dashboard-overview.png` `[~]`

- **Route**: `/`
- **How to reach**: log in. Default landing.
- **What to see**: traffic sparkline + attacks-by-country world
  map + top offending IPs table + panel health card. With the
  v1.3.35 demo seed, all four sub-cards have content.
- **Crop**: full viewport (the layout IS the message).
- **Status note**: pre-v1.3.20 capture; retake to surface the
  v1.3.35 header version pill.
- **Embedded in**: `index.md`,
  `getting-started/first-run.md`, `features/observability.md`

#### `dashboard-security.png` `[x]`

- **Route**: `/` → Security section (scroll within Dashboard)
- **How to reach**: log in; the Security section is mid-page.
- **What to see**: blocked-requests counters + world map of
  attacking IPs + top offenders table.
- **Crop**: just the Security section, not the full Dashboard.
- **Embedded in**: `workflows/respond-to-attack.md`

### 3. Hosts

#### `host-form.png` `[~]`

- **Route**: `/hosts` → click an existing host row
- **How to reach**: log in → Hosts → click any row to open the
  edit modal. Or click "Add host" for the create form.
- **What to see**: domain + target group + TLS mode + TLS email
  + enabled toggle, plus the `Access` fieldset (LAN-only +
  True detect mode) and the optional `Advanced` collapsible
  with ACME CA URL override.
- **Crop**: full modal (it's not too tall).
- **Status note**: RETAKE — modal layout shifted post-v1.3.29
  when `true_detect_mode` was added to the Access fieldset.
- **Embedded in**: `workflows/add-host.md`

#### `host-form-true-detect.png` `[ ]`

- **Route**: `/hosts` → click a host row → modal scrolled to
  Access fieldset
- **How to reach**: apply recipe `host-with-detect-mode` (see
  bottom of file). Capture the Access fieldset with both
  checkboxes visible — the `True detect mode (don't ban on
  AppSec alerts)` row checked, with its sub-text "Alerts
  logged; no LAPI decisions created. Requires
  `setup-appsec.sh` re-run after toggle (script auto-restarts
  crowdsec)." readable.
- **Crop**: Access fieldset only.
- **Status note**: NEW. v1.3.29 feature.
- **Embedded in**: TODO embed in `features/crowdsec.md` AppSec
  subsection.

#### `host-form-dns-provider-dropdown.png` `[x]`

- **Route**: `/hosts` → modal → TLS section
- **How to reach**: open any host's edit modal. With
  `tls_mode=auto`, three challenge radios appear. Select
  `tls_challenge=dns`. The `DNSProviderPicker` renders below
  the radios, populated from globally-enabled providers in
  Settings → DNS providers. The picker is part of the TLS
  section, NOT the Advanced collapsible.
- **What to see**: DNS-01 radio selected + provider dropdown
  with both Cloudflare and Route 53 enabled (so the dropdown
  is populated, not single-option). v1.3.0-beta.
- **Crop**: TLS section card.
- **Embedded in**: `features/dns-providers.md`,
  `release-notes/v1.3.0.md`, `release-notes/v1.3.1.md`

#### `hosts-list-auth-column.png` `[x]`

- **Route**: `/hosts`
- **How to reach**: Hosts page (default). At least one row
  in the demo seed has `auth_required=true` (admin / api /
  vault).
- **What to see**: the row's Auth column shows the lock badge.
- **Crop**: the table including the Auth column header + the
  badge'd rows.
- **Embedded in**: `workflows/publish-with-sso.md`

#### `hosts-detect-badge.png` `[ ]`

- **Route**: `/hosts`
- **How to reach**: apply recipe `host-with-detect-mode` (or
  rely on the demo seed which sets the flag on admin /
  grafana / vault). Then return to `/hosts` and find the row
  with the sky-300 `DETECT` pill alongside the host name.
- **What to see**: hosts list table with the DETECT badge
  visible on at least one row.
- **Crop**: table region with the badge'd row(s).
- **Status note**: NEW. v1.3.29.
- **Embedded in**: TODO embed in `features/crowdsec.md`.

### 4. Target Groups

#### `target-group-form.png` `[x]`

- **Route**: `/target-groups` → "Create target group"
- **How to reach**: log in → Target Groups → "Create" button.
- **What to see**: name / protocol / verify_tls / algorithm /
  health-check fields all visible.
- **Crop**: form card.
- **Embedded in**: `workflows/add-host.md`

#### `target-group-first-target.png` `[x]`

- **Route**: `/target-groups/<id>`
- **How to reach**: from `/target-groups`, click any group's
  row. With the demo seed, every group has exactly one
  target.
- **What to see**: target list with one entry at a LAN address
  (e.g. `192.0.2.10:8080`).
- **Crop**: detail page minus header.
- **Embedded in**: `getting-started/quickstart.md`

#### `target-group-two-targets.png` `[x]`

- **Route**: `/target-groups/<id>`
- **How to reach**: apply recipe `target-group-with-2-targets`
  (see bottom). Capture the detail page once two targets are
  listed.
- **What to see**: target list with two entries at distinct LAN
  addresses, demonstrating multi-target load balancing.
- **Crop**: detail page minus header.
- **Embedded in**: `workflows/add-host.md`

### 5. Security

`/security` is a 5-tab page (Banned IPs / Whitelist / Activity
/ Scenarios / AppSec). KPI/per-host overview lives at a
SEPARATE route, `/security/hosts`. Drift banner + SelfBlock
banner render above the tab strip on `/security` whenever the
matching backend state is set.

#### `security-banned.png` `[ ]`

- **Route**: `/security` → Banned IPs tab (default)
- **How to reach**: log in → Security in the hamburger.
- **What to see**: 100 RFC5737 IPs from the demo LAPI seed —
  CAPI samples + cscli scenarios + AppSec WAF blocks +
  generic. Mix of TTLs, mix of origins.
- **Crop**: full tab body including filters + table.
- **Status note**: NEW. v1.3.20.
- **Embedded in**: TODO embed in `features/crowdsec.md`.

#### `security-whitelist.png` `[ ]`

- **Route**: `/security` → Whitelist tab
- **How to reach**: Security page → click "Whitelist" tab.
- **What to see**: 8 entries with `demo:` reasons (office
  network range, monitoring vendors, VPN exit, CI runners).
- **Crop**: tab body.
- **Status note**: NEW. v1.3.20.
- **Embedded in**: TODO embed in `features/security-overview.md`.

#### `security-activity.png` `[ ]`

- **Route**: `/security` → Activity tab
- **How to reach**: Security page → click "Activity" tab.
- **What to see**: 100 audit-log entries (14-day spread,
  4-user attribution: admin / operator1 / operator2 /
  monitor). Mix of host edits, country bans, drift events,
  cert renewals, target health flips.
- **Crop**: tab body, scroll if needed to show ≥10 rows.
- **Status note**: NEW. v1.3.20.
- **Embedded in**: TODO embed in `features/security-overview.md`.

#### `security-scenarios.png` `[ ]`

- **Route**: `/security` → Scenarios tab
- **How to reach**: Security page → click "Scenarios" tab.
  Hover any row to surface the description tooltip (`ⓘ` glyph).
- **What to see**: scenario list with at least one row hovered
  showing its tooltip. v1.3.30 reverse-sentinel pattern surfaces
  scenario descriptions panel-side.
- **Crop**: tab body with one tooltip visible.
- **Status note**: NEW. v1.3.30.
- **Embedded in**: TODO embed in `features/crowdsec.md`
  Scenarios subsection.

#### `appsec-status.png` `[~]`

- **Route**: `/security` → AppSec tab (NOT the standalone
  `/appsec` page — see entry 7 below for that).
- **How to reach**: Security page → click "AppSec" tab.
- **What to see**: tuning sliders (inbound + outbound
  thresholds) + last-modified-by metadata. The demo seed sets
  inbound=12, outbound=5 (non-default).
- **Crop**: tab body.
- **Status note**: RETAKE — current capture is the pre-v1.3.25
  tuning UI shape; redo against the new sliders.
- **Embedded in**: `features/waf.md`

#### `drift-indicators.png` `[ ]`

- **Route**: `/security` (banner above tab strip + per-tab dots)
- **How to reach**: apply recipe `drift-state-induced` (the
  demo seed already produces both drift surfaces). Capture
  shows the top-of-page amber drift banner AND the amber dots
  next to the Scenarios + AppSec tab labels.
- **What to see**: banner text + both per-tab amber dots.
- **Crop**: top of `/security` page including banner + tab
  strip.
- **Status note**: NEW. v1.3.27.
- **Embedded in**: TODO embed in `features/drift-detection.md`.

#### `selfblock-banner.png` `[ ]`

- **Route**: any panel page (banner is rendered above the page
  body in the layout).
- **How to reach**: apply recipe `self-block-induced` (demo
  only). Reload any page to see the banner.
- **What to see**: red SelfBlockBanner v2 at top of page,
  explaining the operator's IP is currently in a CrowdSec
  ban, with the banned IP + reason + clear-instructions.
- **Crop**: top of page including the full banner.
- **Status note**: NEW. v1.3.20.
- **Embedded in**: TODO embed in `features/security-overview.md`.

#### `security-overview.png` `[x]`

- **Route**: `/security/hosts` (NOT `/security` — separate
  route rendered by `SecurityOverviewPage`, page heading
  "Security overview"). The route is bookmarked from the
  v1.3.24 split when `/security` became the global tab page;
  per-host WAF overview moved here.
- **How to reach**: navigate directly to
  `http://localhost:9181/security/hosts` (no nav link from
  the main hamburger).
- **What to see**: Security overview heading + KPI cards
  (WAF Enabled, Rate Limited, Blocked 24h, Critical Alerts) +
  per-domain table with WAF mode / paranoia / rate limit /
  blocked count / last triggered / action buttons.
- **Crop**: full viewport (cards + table form one logical
  grid).
- **Embedded in**: `features/security-overview.md`

### 6. Threats

`/threats` is a separate top-level route from `/security`.
Both consume CrowdSec decisions data but render different
layouts. Don't conflate.

#### `threats-decisions.png` `[~]`

- **Route**: `/threats`
- **How to reach**: log in → Threats in the hamburger.
- **What to see**: decision list with IP / scenario / duration
  / origin columns + delete buttons. Same underlying CrowdSec
  decisions data as `/security/banned` but a different
  layout/columns. v1.3.35.5 audit confirmed both screenshots
  are valid; `features/crowdsec.md` uses the `/threats` view,
  `/security/banned` will get its own embed in a separate
  feature page.
- **Crop**: full tab body including filters + table.
- **Status note**: RETAKE if the layout has shifted since
  capture; otherwise the file remains valid.
- **Embedded in**: `features/crowdsec.md`

### 7. AppSec

`/appsec` is a separate top-level route from `/security` (the
AppSec tab inside `/security` is the tuning surface; `/appsec`
is the URL+rule-centric metrics page).

#### `appsec-metrics.png` `[x]`

- **Route**: `/appsec` → Metrics sub-tab
- **How to reach**: log in → AppSec in the hamburger →
  Metrics sub-tab.
- **What to see**: hits-per-rule chart + severity distribution
  area chart. With real WAF data, the Y axis is non-zero.
- **Crop**: charts + legend.
- **Embedded in**: `workflows/add-host.md`

### 8. Notifications

#### `notifications-deliveries.png` `[x]`

- **Route**: `/notifications` → Deliveries tab
- **How to reach**: log in → Notifications in the hamburger →
  Deliveries tab.
- **What to see**: status filters + recent attempts list. The
  demo seed produces 250 deliveries across 30 days with mix
  of sent / failed / rate_limited / throttled.
- **Crop**: tab body with stats cards + ≥10 delivery rows.
- **Embedded in**: `features/notifications.md`

### 9. Logs

#### `logs-browser.png` `[x]`

- **Route**: `/logs`
- **How to reach**: log in → Logs in the hamburger.
- **What to see**: range selector on 1h + search + source /
  status / method / path filters + summary KPI cards
  (total + 2xx/4xx/5xx) + rows table with timestamp / source
  badge / host / method / path / status / duration columns.
- **Crop**: full viewport.
- **Embedded in**: `features/logs-browser.md`

### 10. Backup

#### `backup-settings.png` `[x]`

- **Route**: `/system` → Settings → Backup section (NOT
  `/backup` — backup config lives in System Settings).
- **How to reach**: log in → System → Settings → scroll to
  Backup.
- **What to see**: enabled toggle + cron expression field +
  retention days.
- **Crop**: Backup section card.
- **Embedded in**: `features/backups.md`

#### `backups-list.png` `[x]`

- **Route**: `/backup`
- **How to reach**: log in → Backup in the hamburger.
- **What to see**: backups table with mix of scheduled and
  manual entries. The demo seed produces 7 entries (6
  scheduled + 1 manual) over the last week.
- **Crop**: table body, scroll if needed.
- **Embedded in**: `workflows/restore-backup.md`

### 11. System

#### `geoip-status.png` `[x]`

- **Route**: `/system` → GeoIP tab
- **How to reach**: log in → System → GeoIP sub-tab.
- **What to see**: country DB + ASN DB versions + last refresh
  timestamp + Refresh button.
- **Crop**: GeoIP card.
- **Embedded in**: `features/observability.md`

### 12. Settings

#### `settings-panel.png` `[x]`

- **Route**: `/settings`
- **How to reach**: log in → Settings in the hamburger.
- **What to see**: vertical layout with Security section
  (session absolute timeout, idle timeout, panel mode,
  secure cookies info) and Logs section (retention days, max
  entries, save + Purge now buttons).
- **Crop**: full Settings page.
- **Embedded in**: `features/settings.md`

#### `settings-dns-providers.png` `[x]`

- **Route**: `/settings` → DNS providers section
- **How to reach**: Settings page, scroll to DNS providers.
- **What to see**: both Cloudflare + Route 53 cards, with at
  least one in the Configured state (green badge). v1.3.0-beta.
- **Crop**: DNS providers section.
- **Embedded in**: `features/dns-providers.md`,
  `release-notes/v1.3.0.md`, `release-notes/v1.3.1.md`,
  `prereleases/v1.3.0-beta.md`

#### `sso-allowlist.png` `[x]`

- **Route**: `/system` → SSO panel
- **How to reach**: log in → System → SSO sub-tab. Focus the
  Allowed emails textarea so the cursor visible.
- **What to see**: textarea with at least one address per
  line.
- **Crop**: SSO panel card.
- **Embedded in**: `workflows/onboard-admin.md`

### 13. Country bans (under Settings)

#### `country-bans-progress.png` `[ ]`

- **Route**: `/settings` → Country bans section
- **How to reach**: apply recipe `country-ban-in-progress`
  (the demo seed already has 8 countries banned;
  `country-ban-in-progress` triggers a 9th to capture the
  async progress bar live). The progress bar updates with
  `chunks_done / chunks_total` until complete.
- **What to see**: Country bans table + row currently
  expanding with the progress bar visible.
- **Crop**: Country bans section card.
- **Status note**: NEW. v1.3.31.
- **Embedded in**: TODO embed in `features/country-bans.md`.

## Setup recipes

State-changing prerequisites that several captures need.
Reference each recipe by name from a screenshot's "How to
reach". Every recipe with `⚠ Cambia estado:` includes the
revert step.

### Recipe: `host-with-detect-mode`

⚠ Cambia estado: writes `true_detect_mode=true` on a host row.
Revert: re-open modal + uncheck the box + Save (or `argos demo
clear --yes` if you used the demo).

1. Navigate to `/hosts`.
2. Click any host row to open the edit modal (or click
   "Add host" for a fresh form). The demo seed sets the flag
   on `admin.example.com`, `grafana.example.net`, and
   `vault.example.com` already, so on the demo this recipe is
   optional — those rows already render with the DETECT badge.
3. Scroll the modal body to the Access fieldset.
4. Check `True detect mode (don't ban on AppSec alerts)`.
5. Save. The hosts list row now shows the sky-300 DETECT pill.

### Recipe: `drift-state-induced` (demo only)

The v1.3.35.2 demo seed writes `drift_detected:true` into BOTH
`appsec.scenarios.drift_state` and `appsec.tuning.drift_state`,
so the banner + per-tab dots render automatically after
`init.sh`. No additional steps needed against the demo stack.

⚠ Against a real prod stack: out of scope. Don't induce drift
in prod for screenshots — the bandwidth cost is the
operator-facing reload cycle.

### Recipe: `self-block-induced` (demo only)

⚠ Cambia estado: inserts a panel-side settings row that the
SelfBlockBanner v2 reads. Revert with the second command.

```bash
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel \
  /argos demo seed-self-block --yes
# capture the banner on any /security page
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel \
  /argos demo clear-self-block --yes
```

The seed-self-block CLI subcommand was added in v1.3.35.2
specifically so this banner is capturable on demand without
faking a real CrowdSec ban on the operator's own IP.

### Recipe: `country-ban-in-progress`

⚠ Cambia estado: starts a real CrowdSec country expansion.
Revert via the row's revoke button if you want to retry.

1. Navigate to `/settings` → Country bans.
2. Enter an ISO code NOT already in the demo seed's set
   (BR / CN / KR / RU / IR / NG / VN / TR are seeded). E.g.
   `JP` or `AU`.
3. Click "Add country ban".
4. The panel issues `POST /api/security/countries/JP/expand`
   and returns 202 with a job row. The Country bans table
   now has a new row with a progress bar updating
   `chunks_done / chunks_total` live.
5. Capture mid-flow (you have ~10-30s before completion).

### Recipe: `target-group-with-2-targets`

1. Navigate to `/target-groups`.
2. Click "Create target group". Fill in name + protocol +
   algorithm; Save.
3. Click the new group's row to enter the detail page.
4. Click "Add target" twice with two distinct LAN addresses
   (e.g. `192.0.2.10:8080` and `192.0.2.11:8080`).
5. Capture the detail page once two targets are listed.

## Capture session workflow

End-to-end for a "post-vN.N.N captures" commit:

```bash
cd ~/argos-edge

# 1. Bring up the populated demo stack (zero impact on argos-prod).
scripts/demo/init.sh

# 2. Open http://localhost:9181 in a fresh browser window.
#    Log in as demo / demo1234. Pick dark mode.

# 3. For each [ ] / [~] entry above, navigate per "How to reach"
#    and capture per "What to see" + "Crop". Apply any setup
#    recipe the entry references first. Save under
#    docs/screenshots/<filename>.png. PNG only; oxipng or
#    pngquant if >500 KiB.

# 4. Verify the docs portal still builds with the new images.
mkdocs build --strict

# 5. Verify no operator-specific data leaked into the captures
#    (the demo seed uses only RFC 5737 + example.* but a stray
#    LAN URL in a tooltip could still slip in).
./scripts/check-no-personal-data.sh

# 6. Commit. One commit per release, even if multiple files.
git add docs/screenshots/*.png
git commit -m "docs(screenshots): post-vN.N.N captures"

# 7. Tear down the demo stack.
scripts/demo/teardown.sh --purge
```

For each newly-captured `[ ]` entry, also flip the entry's TODO
embed reference into a real `![...]` in the listed feature doc.
That part is a separate doc-only commit; keep it scoped to the
release notes the screenshots ship under.

## Maintenance

When a new feature ships with a UI surface:

1. Add an entry to the inventory above with status `[ ]`,
   filling in Route / How to reach / What to see / Crop /
   Embedded in.
2. If the capture needs state changes, add a Setup recipe.
3. Capture during the release's screenshot session (or note
   the defer in the release notes).
4. Add the `![...]` embed in the feature doc.

When a UI surface gets redesigned:

1. Flip existing entry's status from `[x]` to `[~]`.
2. Add a one-line "Status note" entry explaining what shifted.
3. Schedule the retake against the next release that touches
   the feature.

When a UI surface gets removed:

1. Remove the entry from this inventory.
2. List the embedded-in `.md` files; they'll need either
   removal or replacement of the `![...]` lines (separate
   commit; the inventory rewrite shouldn't touch feature
   pages).

Periodic refresh: every 2-3 doc releases, eyeball the inventory
against the live panel — claims about routes/sections/labels
drift as the UI evolves. The `[~]` markers exist precisely for
this; the v1.3.35.5 audit caught three entries whose locations
had drifted away from reality (DNS picker location, Security
overview route, Threats vs Banned IPs relationship).

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
