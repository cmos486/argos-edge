# Capture session

Read-only Playwright captures of the argos panel for the
docs portal. Lands PNGs in `/tmp/argos-captures-pending/`;
the operator reviews + sanitizes + moves approved files to
`docs/screenshots/`. **The capture script never touches the
repo: no `git add`, no commit, no push.**

## Pre-requisites

- Node 18+ and npm (verified with `node --version`).
- Playwright deps install on first run (~120 MB chromium
  download).
- A `.env` file (gitignored) with operator credentials —
  see "Setup" below.

## Setup

```bash
cd scripts/capture

# 1. Copy the example and fill in your values:
cp .env.example .env
$EDITOR .env
# Required fields: ARGOS_PROD_URL, ARGOS_PROD_USER, ARGOS_PROD_PASS

# 2. Install Playwright + the chromium browser binary.
#    The wrapper scripts run this automatically on first run;
#    do it ahead of time if you want to control the install.
npm ci
npx playwright install chromium
```

`.env` is `git check-ignore`-confirmed: it never enters the
repo. The `.env.example` template is the only env file
committed.

## Run

### Against productive argos

```bash
scripts/capture/run.sh
```

Captures the **24 read-only-safe surfaces** from
`docs/screenshots/README.md`'s inventory:

- Auth: `login.png`
- Dashboard: `dashboard-overview`, `dashboard-security`
- Hosts: `host-form`, `host-form-dns-provider-dropdown`,
  `hosts-list-auth-column`, `hosts-detect-badge` (graceful
  skip if no host has `true_detect_mode=true`)
- Target Groups: `target-group-form`,
  `target-group-first-target`, `target-group-two-targets`
  (graceful skip if no TG has ≥2 targets)
- Security: `security-banned`, `security-whitelist`,
  `security-activity`, `security-scenarios`,
  `appsec-status`, `security-overview` (the
  `/security/hosts` route)
- Threats: `threats-decisions`
- AppSec: `appsec-metrics`
- Notifications: `notifications-deliveries`
- Logs: `logs-browser`
- Backup: `backups-list`
- System: `backup-settings`, `geoip-status`, `sso-allowlist`
- Settings: `settings-panel`, `settings-dns-providers`

Skipped automatically (state-changing in prod) and logged to
`/tmp/argos-captures-pending/.skip-list`:

- `host-form-true-detect.png`
- `drift-indicators.png`
- `selfblock-banner.png`
- `country-bans-progress.png`
- `totp-setup.png`

### Against the demo stack

```bash
# Bring the demo stack up first (separate from prod).
scripts/demo/init.sh

# (Optional) for selfblock-banner specifically:
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel \
  /argos demo seed-self-block --yes

# Capture against demo:
scripts/capture/run-demo.sh

# (Optional) clear the self-block:
docker exec -e ARGOS_DEMO_SEED=1 argos-demo-panel \
  /argos demo clear-self-block --yes
```

`run-demo.sh` defaults to `http://localhost:9181` and credentials
`demo / demo1234` — override with a `scripts/capture/.env.demo`
file (also gitignored). It refuses to run against URLs that
don't look like demo (localhost / 127.x / .lan / .home /
argos-demo*).

## Read-only enforcement

Playwright's `page.click` / `page.fill` are wrapped:

| Wrapper | Guarantees |
|---|---|
| `safeClick(page, selector)` | Reads target's visible text; throws if it matches the 25-pattern blocklist (Save / Add / Delete / Apply / Confirm / Submit / Create / Run / Trigger / Restart / Reset / Send / Disable / Enable / Generate / Regenerate / Revoke / Ban / Unban / Whitelist / Purge / Refresh / Mark applied / Sign out / Logout). |
| `safeHover(page, selector)` | Same blocklist (cheap insurance). |
| `safeFill(_page, _selector, _value)` | **Always throws.** Capture sessions never type into form fields outside the auth flow. |
| `openModal(page, selector, reason)` | Audited escape hatch for click targets that DO match the blocklist text but are confirmed safe (e.g. "Create target group" button — opens client-side modal, no API call). Requires a `reason` string; logged to stdout for traceability. |

`lib/auth.js` is the **only** code that uses raw `page.click` /
`page.fill`. Login is by definition state-changing (creates a
session); after login, every test uses the wrappers.

## Output

```
/tmp/argos-captures-pending/
├── login.png
├── dashboard-overview.png
├── ...
└── .skip-list      (one filename + reason per skipped capture)
```

The directory is wiped at the start of each run.

## Operator workflow post-capture

1. **Review** each PNG in a thumbnail grid. Reject anything that
   looks visually wrong (missing data, error overlay, partial
   render).
2. **Sanitize**: pixelate any operator-specific data
   (real domains, real LAN IPs, real personal email, real bot
   tokens that may have leaked into a tooltip). The demo seed
   uses RFC 5737 IPs + `example.*` hostnames + `demo:` markers
   so its captures are usually safe-as-is — but a stray
   tooltip can still leak.
3. **Move** approved PNGs from `/tmp/argos-captures-pending/`
   to `docs/screenshots/`. **Do not** copy the `.skip-list`
   file.
4. **Commit** with scope `docs(screenshots)`. The capture
   session does NOT run `git add` or `git commit` for you;
   that's deliberate so the operator's review is always in
   the loop.

## Smoke

`scripts/smoke/capture-automation.sh` is a partial smoke
that runs without prod credentials:

- Asserts `run.sh` refuses to run without `.env`.
- Asserts `.env` is `git check-ignore`'d.
- Asserts `safeClick` synthetic test (HTML page with a "Save"
  button) throws the expected error.
- Asserts the repo working tree stays clean across a mocked
  capture run.

The full end-to-end smoke (login + 24 captures) requires a
real productive panel + credentials; the operator runs that
manually post-deploy. There's no CI path for the full smoke
because the credentials are operator-secret.

## Troubleshooting

- **"npm ci" fails** — ensure Node 18+ and `package-lock.json`
  is present (auto-generated on first run; commit it).
- **Login fails with timeout** — the panel's login form may
  use OIDC if SSO is the configured default; the auth helper
  expects username + password fields. If your prod is
  OIDC-only, the auto-capture flow won't work; fall back to
  manual capture.
- **safeClick blocks a click that's actually safe** — audit
  the click site, then either use `openModal` with a reason
  string (audited override) OR refine the `BLOCKED_TEXT_PATTERNS`
  list in `lib/safe-page.js`.
- **Capture is blank / dark / clipped** — bump
  `page.waitForTimeout` in the failing test, or check the
  `await page.waitForLoadState('networkidle')` deadline; some
  surfaces have charts that take a beat to render.

## Versioning

Capture tooling versions independently from the panel binary.
`package.json` `version` field tracks tag releases of this
folder; `argosVersion` and `frontend/package.json` are
unrelated.
