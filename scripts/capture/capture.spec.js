// Read-only capture spec for argos panel screenshots.
//
// This file is consumed by both the prod run (scripts/capture/run.sh)
// and the demo run (scripts/capture/run-demo.sh). The active mode
// is signalled via ARGOS_CAPTURE_MODE:
//
//   ARGOS_CAPTURE_MODE=prod     -- the 24 read-only-safe surfaces
//   ARGOS_CAPTURE_MODE=demo     -- the 24 + 5 demo-only state-dependent
//                                  surfaces
//   (default = prod when unset; safest)
//
// Output goes to ARGOS_OUTPUT_DIR (default /tmp/argos-captures-pending/).
// Skip-list rows (capture intentionally not attempted in this mode)
// land in $OUTPUT/.skip-list as one filename per line.
//
// Read-only contract:
//   - safeClick (lib/safe-page.js) blocks 25 state-mutating verbs.
//   - safeFill is a hard-throw for everything outside the auth flow.
//   - openModal is the audited escape hatch for client-side-only
//     modal-open clicks (Create button, row click).

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const { loginToPanel } = require('./lib/auth');
const { safeClick, safeHover, openModal } = require('./lib/safe-page');

const MODE = process.env.ARGOS_CAPTURE_MODE || 'prod';
const OUTPUT_DIR = process.env.ARGOS_OUTPUT_DIR || '/tmp/argos-captures-pending';
const SKIP_LIST_PATH = path.join(OUTPUT_DIR, '.skip-list');

// Ensure output dir exists at module load (test-runner doesn't pre-
// create dirs and a missing /tmp subdir would make the first
// page.screenshot() throw an ENOENT before our skip-list is written).
fs.mkdirSync(OUTPUT_DIR, { recursive: true });
// Truncate skip-list at the start of each run so it reflects only
// this invocation. Captures append per-test on skip.
fs.writeFileSync(SKIP_LIST_PATH, '');

// Helpers --------------------------------------------------------------

async function shotFull(page, name) {
  await page.screenshot({
    path: path.join(OUTPUT_DIR, `${name}.png`),
    fullPage: false, // viewport only; the README's "full viewport" guidance is the 1440x900 frame.
  });
}

function shotPath(name) {
  return path.join(OUTPUT_DIR, `${name}.png`);
}

function logSkip(name, reason) {
  fs.appendFileSync(SKIP_LIST_PATH, `${name}\t${reason}\n`);
  // eslint-disable-next-line no-console
  console.log(`[skip] ${name}: ${reason}`);
}

function isProd() { return MODE === 'prod'; }
function isDemo() { return MODE === 'demo'; }

// Shared session login once for the whole run (single worker).
test.beforeAll(async ({ browser }) => {
  // The browser-context wide login lives in the page used by the
  // first test; subsequent tests in the same worker share its
  // cookies via the project's persistent storage state.
});

test.describe.configure({ mode: 'serial' });

// --- Auth ---

test('1. login.png', async ({ page }) => {
  await page.goto('/login');
  await page.waitForSelector('input[type="text"], input[name="username"]');
  await shotFull(page, 'login');
});

// Every test below assumes we're logged in. The auth fixture runs
// at the start of the second test (after we've captured the
// pre-login form) so login state persists for the rest.

test('2. auth: log in for remaining captures', async ({ page }) => {
  await loginToPanel(page);
});

// --- Dashboard ---

test('3. dashboard-overview.png', async ({ page }) => {
  await page.goto('/');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500); // let charts render
  await shotFull(page, 'dashboard-overview');
});

test('4. dashboard-security.png', async ({ page }) => {
  await page.goto('/');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // Scroll to the Security section -- card heading "Security" or
  // "Attack origins" is the anchor; tolerant if either isn't
  // findable.
  try {
    const heading = page.locator('h2, h3').filter({ hasText: /security|attacks?|origins/i }).first();
    await heading.scrollIntoViewIfNeeded({ timeout: 5_000 });
  } catch { /* fall back to viewport-as-is */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'dashboard-security');
});

// --- Hosts ---

test('5. hosts-list-auth-column.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table', { timeout: 10_000 });
  await page.waitForTimeout(300);
  await shotFull(page, 'hosts-list-auth-column');
});

test('6. host-form.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // First host row click opens the edit modal. Audited safe:
  // openCreate / openEdit on the page only flips local React state
  // (no API call). Verified for v1.3.35.x: api.updateHost only
  // fires on form onSubmit, not on row click.
  await openModal(page, 'table tbody tr:first-child', 'opens host edit modal (client-side state)');
  await page.waitForSelector('[role="dialog"], .modal, h2:has-text("Edit"), h2:has-text("Host")', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(300);
  await shotFull(page, 'host-form');
  // Close modal via Escape; capture session must NOT submit.
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

test('7. host-form-dns-provider-dropdown.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  await openModal(page, 'table tbody tr:first-child', 'opens host edit modal');
  await page.waitForTimeout(300);
  // Inside the modal, the TLS section has three challenge radios
  // (DNS-01, HTTP-01, TLS-ALPN-01). Click the DNS-01 label -- this
  // is uncommitted form-state inside the modal; the picker renders
  // when tls_challenge==='dns'. We do NOT save.
  try {
    // Try to find the DNS label first; fall back to the value=dns radio.
    const dnsRadio = page.locator('input[type="radio"][value="dns"]').first();
    if (await dnsRadio.count()) {
      await openModal(page, 'input[type="radio"][value="dns"]', 'selects DNS-01 in form (uncommitted)');
    }
  } catch { /* the form may already be on DNS-01; tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'host-form-dns-provider-dropdown');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

// host-form-true-detect.png + hosts-detect-badge.png:
// require an existing host with true_detect_mode=true. In prod we
// attempt + skip gracefully; in demo the seed produces three.

test('8. hosts-detect-badge.png (graceful skip if no match)', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // Look for the DETECT badge on any row.
  const detectBadge = page.locator('table tbody tr').filter({ has: page.locator('text=/^DETECT$/') }).first();
  if (await detectBadge.count() === 0) {
    logSkip('hosts-detect-badge', 'no host with true_detect_mode=true in this stack');
    test.skip();
    return;
  }
  await detectBadge.scrollIntoViewIfNeeded();
  await page.waitForTimeout(300);
  await shotFull(page, 'hosts-detect-badge');
});

test('9. host-form-true-detect.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('host-form-true-detect', 'state-changing in prod (would require enabling flag); capture against demo');
    test.skip();
    return;
  }
  // Demo path: open the first host with true_detect_mode (admin /
  // grafana / vault per demo seed) and capture the Access fieldset.
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // Find the row with the DETECT badge first, then open its modal.
  const row = page.locator('table tbody tr').filter({ has: page.locator('text=/^DETECT$/') }).first();
  if (await row.count() === 0) {
    logSkip('host-form-true-detect', 'demo seed has no DETECT-flagged host (was demo seeded?)');
    test.skip();
    return;
  }
  await openModal(page, 'table tbody tr:has(span:has-text("DETECT"))', 'opens host edit modal for detect host');
  await page.waitForTimeout(300);
  // Scroll to Access fieldset.
  try {
    const access = page.locator('fieldset:has(legend:has-text("Access"))').first();
    await access.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate; full modal capture if scroll fails */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'host-form-true-detect');
  await page.keyboard.press('Escape');
});

// --- Target Groups ---

test('10. target-group-form.png', async ({ page }) => {
  await page.goto('/target-groups');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // The "Create target group" button opens a client-side form; no
  // API call until submit. Verified TargetGroups.tsx: openCreate
  // sets local state only, api.createTargetGroup only fires on
  // onSubmit which we never trigger.
  await openModal(
    page,
    'button:has-text("Create"), button:has-text("New target group"), [data-testid="create-tg"]',
    'opens TG create form (client-side state)',
  );
  await page.waitForTimeout(300);
  await shotFull(page, 'target-group-form');
  await page.keyboard.press('Escape');
});

test('11. target-group-first-target.png', async ({ page }) => {
  await page.goto('/target-groups');
  await page.waitForSelector('table tbody tr a, [href*="/target-groups/"]', { timeout: 10_000 });
  // Follow the first row's link to the detail page.
  const firstLink = page.locator('table tbody tr a, [href*="/target-groups/"]').first();
  const href = await firstLink.getAttribute('href');
  if (!href) {
    logSkip('target-group-first-target', 'no target group rows to follow');
    test.skip();
    return;
  }
  await page.goto(href);
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(300);
  await shotFull(page, 'target-group-first-target');
});

test('12. target-group-two-targets.png (graceful skip if no match)', async ({ page }) => {
  await page.goto('/target-groups');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // Find a row whose targets-count column shows >= 2.
  const rows = page.locator('table tbody tr');
  const count = await rows.count();
  let twoTargetHref = null;
  for (let i = 0; i < count; i++) {
    const row = rows.nth(i);
    const text = (await row.textContent()) || '';
    // Heuristic: look for "2 targets" / "3 targets" / etc.
    if (/\b([2-9]|\d{2,})\s*targets?\b/i.test(text)) {
      const link = row.locator('a').first();
      if (await link.count()) twoTargetHref = await link.getAttribute('href');
      break;
    }
  }
  if (!twoTargetHref) {
    logSkip('target-group-two-targets', 'no TG with >= 2 targets in this stack; capture against demo');
    test.skip();
    return;
  }
  await page.goto(twoTargetHref);
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(300);
  await shotFull(page, 'target-group-two-targets');
});

// --- Security (5-tab page + drift banner + selfblock banner) ---

test('13. security-banned.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('table, [role="tablist"]', { timeout: 10_000 });
  await page.waitForTimeout(500);
  await shotFull(page, 'security-banned');
});

test('14. security-whitelist.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('[role="tablist"], button:has-text("Whitelist")', { timeout: 10_000 });
  await safeClick(page, 'button:has-text("Whitelist")');
  await page.waitForTimeout(500);
  await shotFull(page, 'security-whitelist');
});

test('15. security-activity.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("Activity")', { timeout: 10_000 });
  await safeClick(page, 'button:has-text("Activity")');
  await page.waitForTimeout(500);
  await shotFull(page, 'security-activity');
});

test('16. security-scenarios.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("Scenarios")', { timeout: 10_000 });
  await safeClick(page, 'button:has-text("Scenarios")');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // Hover the first scenario row to surface the description tooltip
  // (v1.3.30 reverse-sentinel surface).
  await safeHover(page, 'table tbody tr:first-child');
  await page.waitForTimeout(800); // tooltip render delay
  await shotFull(page, 'security-scenarios');
});

test('17. appsec-status.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("AppSec")', { timeout: 10_000 });
  await safeClick(page, 'button:has-text("AppSec")');
  await page.waitForTimeout(500);
  await shotFull(page, 'appsec-status');
});

test('18. drift-indicators.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('drift-indicators', 'state-changing in prod; capture against demo (drift seed pre-set)');
    test.skip();
    return;
  }
  await page.goto('/security');
  // Wait for the banner OR the per-tab dot to render.
  try {
    await page.waitForSelector('text=/drift detected|Configuration drift/i', { timeout: 5_000 });
  } catch {
    logSkip('drift-indicators', 'demo did not render drift banner (drift_state.drift_detected=false?)');
    test.skip();
    return;
  }
  await page.waitForTimeout(300);
  await shotFull(page, 'drift-indicators');
});

test('19. selfblock-banner.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('selfblock-banner', 'state-changing in prod (would ban operator IP); capture against demo via seed-self-block');
    test.skip();
    return;
  }
  // Demo: the operator must run `argos demo seed-self-block --yes`
  // BEFORE running this capture. Detect the banner; if absent,
  // skip + log.
  await page.goto('/');
  try {
    await page.waitForSelector('text=/self.?block|currently.+ban/i', { timeout: 3_000 });
  } catch {
    logSkip('selfblock-banner', 'demo SelfBlockBanner not present; run `argos demo seed-self-block --yes` first');
    test.skip();
    return;
  }
  await page.waitForTimeout(300);
  await shotFull(page, 'selfblock-banner');
});

test('20. security-overview.png', async ({ page }) => {
  // Separate route from /security; rendered by SecurityOverviewPage.
  await page.goto('/security/hosts');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFull(page, 'security-overview');
});

// --- Threats ---

test('21. threats-decisions.png', async ({ page }) => {
  await page.goto('/threats');
  await page.waitForSelector('table, [role="tabpanel"]', { timeout: 10_000 });
  await page.waitForTimeout(500);
  await shotFull(page, 'threats-decisions');
});

// --- AppSec (separate route from /security AppSec tab) ---

test('22. appsec-metrics.png', async ({ page }) => {
  await page.goto('/appsec');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // The Metrics sub-tab; click only if there's a sub-tab strip.
  const metricsTab = page.locator('button:has-text("Metrics")').first();
  if (await metricsTab.count()) {
    await safeClick(page, 'button:has-text("Metrics")');
  }
  await page.waitForTimeout(500);
  await shotFull(page, 'appsec-metrics');
});

// --- Notifications ---

test('23. notifications-deliveries.png', async ({ page }) => {
  await page.goto('/notifications');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // The "Deliveries" tab is one of several; click if present.
  const deliveriesTab = page.locator('button:has-text("Deliveries")').first();
  if (await deliveriesTab.count()) {
    await safeClick(page, 'button:has-text("Deliveries")');
  }
  await page.waitForTimeout(500);
  await shotFull(page, 'notifications-deliveries');
});

// --- Logs ---

test('24. logs-browser.png', async ({ page }) => {
  await page.goto('/logs');
  await page.waitForSelector('table, [role="grid"]', { timeout: 10_000 });
  await page.waitForTimeout(500);
  await shotFull(page, 'logs-browser');
});

// --- Backup ---

test('25. backups-list.png', async ({ page }) => {
  await page.goto('/backup');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFull(page, 'backups-list');
});

// --- System ---

test('26. backup-settings.png', async ({ page }) => {
  // System -> Settings -> Backup section. Heuristic: Backup card
  // anchor on the /system page.
  await page.goto('/system');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // Try scrolling to a Backup heading.
  try {
    const backup = page.locator('h2, h3, [data-section="backup"]').filter({ hasText: /backup/i }).first();
    await backup.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'backup-settings');
});

test('27. geoip-status.png', async ({ page }) => {
  await page.goto('/system');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // GeoIP card / sub-tab.
  try {
    const geoip = page.locator('h2, h3, [data-section="geoip"]').filter({ hasText: /geoip|geo ip/i }).first();
    await geoip.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'geoip-status');
});

test('28. sso-allowlist.png', async ({ page }) => {
  await page.goto('/system');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  try {
    const sso = page.locator('h2, h3').filter({ hasText: /SSO|single sign|OIDC/i }).first();
    await sso.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'sso-allowlist');
});

test('29. totp-setup.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('totp-setup', 'state-changing in prod (enables 2FA); capture against fresh demo only');
    test.skip();
    return;
  }
  await page.goto('/system');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // Open the Two-factor setup dialog. THIS IS DELIBERATELY ALLOWED
  // ON DEMO ONLY because the demo's auth state is throwaway. Even
  // so, we use openModal so the click is logged in the audit
  // transcript.
  try {
    await openModal(page, 'button:has-text("Enable")', 'opens TOTP enrollment dialog (demo only)');
    await page.waitForSelector('text=/scan.+QR|recovery codes/i', { timeout: 5_000 });
    await page.waitForTimeout(500);
    await shotFull(page, 'totp-setup');
  } catch (e) {
    logSkip('totp-setup', `dialog did not render (already enabled?): ${e.message}`);
    test.skip();
    return;
  }
  // Cancel the dialog; do NOT confirm (would actually enable 2FA).
  await page.keyboard.press('Escape');
});

// --- Settings ---

test('30. settings-panel.png', async ({ page }) => {
  await page.goto('/settings');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFull(page, 'settings-panel');
});

test('31. settings-dns-providers.png', async ({ page }) => {
  await page.goto('/settings');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  try {
    const dns = page.locator('h2, h3').filter({ hasText: /DNS providers?/i }).first();
    await dns.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'settings-dns-providers');
});

// --- Country bans (under Settings; demo-only state-dependent) ---

test('32. country-bans-progress.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('country-bans-progress', 'state-changing in prod (triggers real expansion); capture against demo');
    test.skip();
    return;
  }
  await page.goto('/settings');
  await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});
  // Demo seed has 8 country bans; one MAY be in 'drifted' state but
  // there's no in-flight expansion at idle. The capture would ideally
  // catch a mid-expansion progress bar, which requires manual trigger.
  // For now: capture the static Country bans table so the surface is
  // at least represented.
  try {
    const cb = page.locator('h2, h3').filter({ hasText: /country ban/i }).first();
    await cb.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'country-bans-progress');
});

// Final hook: emit a summary block to stdout so the wrapper script
// can paste it into the operator's terminal.
test.afterAll(async () => {
  const captured = fs.readdirSync(OUTPUT_DIR)
    .filter((f) => f.endsWith('.png'))
    .sort();
  // eslint-disable-next-line no-console
  console.log('');
  // eslint-disable-next-line no-console
  console.log(`==========================================`);
  // eslint-disable-next-line no-console
  console.log(`mode=${MODE}  output=${OUTPUT_DIR}`);
  // eslint-disable-next-line no-console
  console.log(`captures=${captured.length}`);
  // eslint-disable-next-line no-console
  console.log(`skipped=$(wc -l < ${SKIP_LIST_PATH} 2>/dev/null || echo 0)`);
  // eslint-disable-next-line no-console
  console.log(`==========================================`);
});
