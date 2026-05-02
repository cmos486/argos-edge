// Read-only capture spec for argos panel screenshots.
//
// v1.3.36.1 changes (vs v1.3.36):
//   - Auth state now persisted via auth.setup.js (a separate
//     Playwright "setup" project) + use.storageState in the
//     captures project. v1.3.36 had an empty test.beforeAll
//     and per-test fixture pages, so cookies didn't persist
//     between tests; every post-login capture was silently a
//     /login redirect.
//   - login.png captures wrapped in test.describe with
//     test.use({ storageState: ... }) override so the login
//     page renders un-authenticated.
//   - Banner output uses fs.readFileSync to count skip lines
//     (v1.3.36 had `$(wc -l ...)` literal in a JS template
//     string; never expanded).
//   - shotFullScroll() helper: fullPage:true for long-list
//     surfaces (security tabs, hosts list, deliveries, etc.).
//     shotFull() unchanged for above-fold / modal surfaces.
//
// Read-only contract unchanged: safeClick blocklist + safeFill
// hard-throw + openModal audited escape hatch.

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const { safeClick, safeHover, openModal, safeClickTab } = require('./lib/safe-page');

const MODE = process.env.ARGOS_CAPTURE_MODE || 'prod';
const OUTPUT_DIR = process.env.ARGOS_OUTPUT_DIR || '/tmp/argos-captures-pending';
const SKIP_LIST_PATH = path.join(OUTPUT_DIR, '.skip-list');

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.writeFileSync(SKIP_LIST_PATH, '');

// Helpers --------------------------------------------------------------

// waitForSettled: networkidle with a fallback fixed wait when
// networkidle never resolves (e.g. surfaces with continuous polling
// like the dashboard's 30s health-check interval, or AppSec status
// being repolled). Default behaviour:
//   - Try networkidle for `timeout` ms (default 10s).
//   - On timeout, sleep `fallback` ms (default 3s) so async data
//     has at least some chance to land.
// v1.3.36.2: captures pre-this-helper fired the screenshot
// immediately after goto, so dashboards + listing tables showed
// skeleton/loading states. Use this between every goto/tab-click
// and the screenshot call.
async function waitForSettled(page, opts = {}) {
  const { timeout = 10_000, fallback = 3_000 } = opts;
  try {
    await page.waitForLoadState('networkidle', { timeout });
  } catch {
    await page.waitForTimeout(fallback);
  }
}

// shotFull: viewport-only screenshot. Use for above-fold surfaces
// (login form, dashboard cards, modals) where fullPage would just
// add empty space below the meaningful content.
async function shotFull(page, name) {
  await page.screenshot({
    path: path.join(OUTPUT_DIR, `${name}.png`),
    fullPage: false,
  });
}

// shotFullScroll: full-page screenshot covering the entire scrollable
// content. Use for long-list surfaces (security tabs with N rows,
// notifications deliveries, hosts list, scenarios, etc.) where the
// viewport-only frame would clip most of the data.
async function shotFullScroll(page, name) {
  await page.screenshot({
    path: path.join(OUTPUT_DIR, `${name}.png`),
    fullPage: true,
  });
}

function logSkip(name, reason) {
  fs.appendFileSync(SKIP_LIST_PATH, `${name}\t${reason}\n`);
  // eslint-disable-next-line no-console
  console.log(`[skip] ${name}: ${reason}`);
}

function isProd() { return MODE === 'prod'; }

test.describe.configure({ mode: 'serial' });

// --- Auth: login.png is the ONLY capture that needs an
// un-authenticated browser context. The describe-level use override
// gives this block a fresh empty storageState (vs the project-level
// authenticated state). ---

test.describe('login (anon)', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('1. login.png', async ({ page }) => {
    await page.goto('/login');
    await page.waitForSelector('input[type="text"], input[name="username"]', { timeout: 10_000 });
    await shotFull(page, 'login');
  });
});

// All tests below inherit project-level use.storageState =
// /tmp/argos-auth-state.json (written by auth.setup.js). That state
// is loaded automatically into each test's BrowserContext by
// Playwright; cookies persist for the duration of the run.

// --- Dashboard ---

test('2. dashboard-overview.png', async ({ page }) => {
  await page.goto('/');
  await waitForSettled(page);
  // Dashboard cards animate in; let the chart libs render.
  await page.waitForTimeout(800);
  await shotFull(page, 'dashboard-overview');
});

test('3. dashboard-security.png', async ({ page }) => {
  await page.goto('/');
  await waitForSettled(page);
  try {
    const heading = page.locator('h2, h3').filter({ hasText: /security|attacks?|origins/i }).first();
    await heading.scrollIntoViewIfNeeded({ timeout: 5_000 });
  } catch { /* fall back to viewport-as-is */ }
  // World map + top-IPs table need extra render time.
  await page.waitForTimeout(800);
  await shotFull(page, 'dashboard-security');
});

// --- Hosts ---

test('4. hosts-list-auth-column.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  await waitForSettled(page);
  await page.waitForTimeout(300);
  // Long-list surface: prod can have many hosts, demo seed has 14.
  await shotFullScroll(page, 'hosts-list-auth-column');
});

test('5. host-form.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // v1.3.36.4 trigger fix: rows are NOT clickable on /hosts. The
  // edit modal is opened by the IconButton with aria-label="edit"
  // (a Pencil icon) inside the row's last <td>. Hosts.tsx:442
  // wires onClick={() => openEdit(h)}; IconButton renders as
  // <button aria-label="edit" title="edit">. v1.3.36.3 clicked
  // <tr>, which has no onClick, so setModalOpen(true) never
  // fired and the modal-visibility wait timed out.
  //
  // Modal selector: the panel's <Modal> component renders an
  // overlay `<div class="fixed inset-0 z-40 ...">`. Same class set
  // for every modal in the panel; openModal waits for it visible +
  // 400ms animation settle (no animation in practice -- modal
  // mounts synchronously when open=true).
  await openModal(
    page,
    'table tbody tr:first-child button[aria-label="edit"]',
    'opens host edit modal (client-side state)',
    '.fixed.inset-0.z-40',
  );
  await shotFull(page, 'host-form');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

test('6. host-form-dns-provider-dropdown.png', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  // Open the host edit modal first. See test 5 above for why we
  // click the aria-label="edit" button instead of the row.
  await openModal(
    page,
    'table tbody tr:first-child button[aria-label="edit"]',
    'opens host edit modal',
    '.fixed.inset-0.z-40',
  );
  // Select DNS-01 inside the open modal.
  //
  // v1.3.36.5: prior versions used selector
  //   'input[type="radio"][value="dns"]'
  // which matched ZERO elements -- the panel's <ChallengeRadio>
  // (Hosts.tsx:808-836) renders the radio with name="tls-challenge"
  // but NO value attribute. The differentiator is the wrapping
  // <label>'s visible text ("DNS-01" / "HTTP-01" / "TLS-ALPN-01").
  // The defensive `if (count) {...}` made the failure silent: zero
  // elements -> no click -> modal stayed in default state -> capture
  // showed the modal without DNS-01 selected and without the picker
  // rendered.
  //
  // Fix: click the <label> by its visible text. Clicking the label
  // fires the inner <input>'s onChange via standard HTML semantics
  // (label wraps input). The <label> text contains "DNS-01" + the
  // hint string; neither matches any blocklist pattern, so safeClick
  // is the right wrapper here (no openModal -- the click doesn't
  // open a new modal, it changes form state inside an existing one).
  try {
    await safeClick(page, 'label:has-text("DNS-01")');
  } catch { /* tolerate if DNS already selected or label missing */ }
  // 400ms covers the React render tick + any single-frame paint
  // for the DNSProviderPicker. Per Hosts.tsx:553-559, the picker
  // renders synchronously when tls_challenge==='dns'; one of three
  // shapes (multi-provider <select>, singleton "Using <name>", or
  // amber-warning) -- all valid post-DNS-01 captures.
  await page.waitForTimeout(400);
  await shotFull(page, 'host-form-dns-provider-dropdown');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);
});

test('7. hosts-detect-badge.png (graceful skip if no match)', async ({ page }) => {
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  const detectBadge = page.locator('table tbody tr').filter({ has: page.locator('text=/^DETECT$/') }).first();
  if (await detectBadge.count() === 0) {
    logSkip('hosts-detect-badge', 'no host with true_detect_mode=true in this stack');
    test.skip();
    return;
  }
  await detectBadge.scrollIntoViewIfNeeded();
  await page.waitForTimeout(300);
  await shotFullScroll(page, 'hosts-detect-badge');
});

test('8. host-form-true-detect.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('host-form-true-detect', 'state-changing in prod (would require enabling flag); capture against demo');
    test.skip();
    return;
  }
  await page.goto('/hosts');
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  const row = page.locator('table tbody tr').filter({ has: page.locator('text=/^DETECT$/') }).first();
  if (await row.count() === 0) {
    logSkip('host-form-true-detect', 'demo seed has no DETECT-flagged host (was demo seeded?)');
    test.skip();
    return;
  }
  // Same trigger pattern as tests 5/6: click the row's edit button
  // (aria-label="edit"), not the row itself. Scope to the row that
  // contains the DETECT badge.
  await openModal(
    page,
    'table tbody tr:has(span:has-text("DETECT")) button[aria-label="edit"]',
    'opens host edit modal for detect host',
    '.fixed.inset-0.z-40',
  );
  try {
    const access = page.locator('fieldset:has(legend:has-text("Access"))').first();
    await access.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(300);
  await shotFull(page, 'host-form-true-detect');
  await page.keyboard.press('Escape');
});

// --- Target Groups ---

test('9. target-group-form.png', async ({ page }) => {
  await page.goto('/target-groups');
  await waitForSettled(page);
  // v1.3.36.3 selector fix: real button text is "Add target group"
  // (per TargetGroups.tsx:60-67). v1.3.36.x had "Create" / "New
  // target group" / [data-testid="create-tg"] — none matched, so
  // openModal timed out at 10s.
  await openModal(
    page,
    'button:has-text("Add target group")',
    'opens TG create form (client-side state)',
    '.fixed.inset-0.z-40',
  );
  await shotFull(page, 'target-group-form');
  await page.keyboard.press('Escape');
});

test('10. target-group-first-target.png', async ({ page }) => {
  await page.goto('/target-groups');
  await page.waitForSelector('table tbody tr a, [href*="/target-groups/"]', { timeout: 10_000 });
  const firstLink = page.locator('table tbody tr a, [href*="/target-groups/"]').first();
  const href = await firstLink.getAttribute('href');
  if (!href) {
    logSkip('target-group-first-target', 'no target group rows to follow');
    test.skip();
    return;
  }
  await page.goto(href);
  await waitForSettled(page);
  await page.waitForTimeout(400);
  await shotFull(page, 'target-group-first-target');
});

test('11. target-group-two-targets.png (graceful skip if no match)', async ({ page }) => {
  await page.goto('/target-groups');
  await waitForSettled(page);
  const rows = page.locator('table tbody tr');
  const count = await rows.count();
  let twoTargetHref = null;
  for (let i = 0; i < count; i++) {
    const row = rows.nth(i);
    const text = (await row.textContent()) || '';
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
  await waitForSettled(page);
  await page.waitForTimeout(400);
  await shotFull(page, 'target-group-two-targets');
});

// --- Security ---

test('12. security-banned.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('table, [role="tablist"]', { timeout: 10_000 });
  await waitForSettled(page);
  // Banned IPs tab is the default; wait for at least one decision row
  // before screenshotting. Empty state ("no banned IPs") is also valid;
  // tolerate via a 5s timeout.
  await page.waitForSelector('table tbody tr', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'security-banned');
});

test('13. security-whitelist.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('[role="tablist"], button:has-text("Whitelist")', { timeout: 10_000 });
  await safeClickTab(page, 'button:has-text("Whitelist")', 'switch to Whitelist tab');
  await waitForSettled(page);
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'security-whitelist');
});

test('14. security-activity.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("Activity")', { timeout: 10_000 });
  await safeClickTab(page, 'button:has-text("Activity")', 'switch to Activity tab');
  await waitForSettled(page);
  // Activity tab queries the audit log; wait for rows.
  await page.waitForSelector('table tbody tr, [role="row"]', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'security-activity');
});

test('15. security-scenarios.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("Scenarios")', { timeout: 10_000 });
  await safeClickTab(page, 'button:has-text("Scenarios")', 'switch to Scenarios tab');
  await waitForSettled(page);
  await page.waitForSelector('table tbody tr', { timeout: 10_000 });
  await safeHover(page, 'table tbody tr:first-child');
  await page.waitForTimeout(800); // tooltip render delay
  await shotFullScroll(page, 'security-scenarios');
});

test('16. appsec-status.png', async ({ page }) => {
  await page.goto('/security');
  await page.waitForSelector('button:has-text("AppSec")', { timeout: 10_000 });
  await safeClickTab(page, 'button:has-text("AppSec")', 'switch to AppSec tab');
  await waitForSettled(page);
  await page.waitForTimeout(500);
  await shotFull(page, 'appsec-status');
});

test('17. drift-indicators.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('drift-indicators', 'state-changing in prod; capture against demo (drift seed pre-set)');
    test.skip();
    return;
  }
  await page.goto('/security');
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

test('18. selfblock-banner.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('selfblock-banner', 'state-changing in prod (would ban operator IP); capture against demo via seed-self-block');
    test.skip();
    return;
  }
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

test('19. security-overview.png', async ({ page }) => {
  await page.goto('/security/hosts');
  await waitForSettled(page);
  // Per-host KPI table needs the security overview API to land.
  await page.waitForSelector('table tbody tr, [role="row"]', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'security-overview');
});

// --- Threats ---

test('20. threats-decisions.png', async ({ page }) => {
  await page.goto('/threats');
  await page.waitForSelector('table, [role="tabpanel"]', { timeout: 10_000 });
  await waitForSettled(page);
  // Decisions list comes from CrowdSec LAPI.
  await page.waitForSelector('table tbody tr', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'threats-decisions');
});

// --- AppSec ---

test('21. appsec-metrics.png', async ({ page }) => {
  await page.goto('/appsec');
  await waitForSettled(page);
  const metricsTab = page.locator('button:has-text("Metrics")').first();
  if (await metricsTab.count()) {
    await safeClickTab(page, 'button:has-text("Metrics")', 'switch to Metrics sub-tab');
    await waitForSettled(page);
  }
  // Charts (recharts) render asynchronously after data arrival.
  await page.waitForTimeout(800);
  await shotFull(page, 'appsec-metrics');
});

// --- Notifications ---

test('22. notifications-deliveries.png', async ({ page }) => {
  await page.goto('/notifications');
  await waitForSettled(page);
  const deliveriesTab = page.locator('button:has-text("Deliveries")').first();
  if (await deliveriesTab.count()) {
    await safeClickTab(page, 'button:has-text("Deliveries")', 'switch to Deliveries tab');
    await waitForSettled(page);
  }
  // Deliveries query can return up to ~250 rows in demo.
  await page.waitForSelector('table tbody tr', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'notifications-deliveries');
});

// --- Logs ---

test('23. logs-browser.png', async ({ page }) => {
  await page.goto('/logs');
  await page.waitForSelector('table, [role="grid"]', { timeout: 10_000 });
  await waitForSettled(page);
  await page.waitForSelector('table tbody tr, [role="grid"] [role="row"]', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'logs-browser');
});

// --- Backup ---

test('24. backups-list.png', async ({ page }) => {
  await page.goto('/backup');
  await waitForSettled(page);
  await page.waitForSelector('table tbody tr', { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'backups-list');
});

// --- System ---

test('25. backup-settings.png', async ({ page }) => {
  await page.goto('/system');
  await waitForSettled(page);
  try {
    const backup = page.locator('h2, h3, [data-section="backup"]').filter({ hasText: /backup/i }).first();
    await backup.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(400);
  await shotFull(page, 'backup-settings');
});

test('26. geoip-status.png', async ({ page }) => {
  await page.goto('/system');
  await waitForSettled(page);
  try {
    const geoip = page.locator('h2, h3, [data-section="geoip"]').filter({ hasText: /geoip|geo ip/i }).first();
    await geoip.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(400);
  await shotFull(page, 'geoip-status');
});

test('27. sso-allowlist.png', async ({ page }) => {
  await page.goto('/system');
  await waitForSettled(page);
  try {
    const sso = page.locator('h2, h3').filter({ hasText: /SSO|single sign|OIDC/i }).first();
    await sso.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(400);
  await shotFull(page, 'sso-allowlist');
});

test('28. totp-setup.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('totp-setup', 'state-changing in prod (enables 2FA); capture against fresh demo only');
    test.skip();
    return;
  }
  await page.goto('/system');
  await waitForSettled(page);
  try {
    await openModal(
      page,
      'button:has-text("Enable")',
      'opens TOTP enrollment dialog (demo only)',
      '.fixed.inset-0.z-40',
    );
    await page.waitForSelector('text=/scan.+QR|recovery codes/i', { timeout: 5_000 });
    await page.waitForTimeout(500);
    await shotFull(page, 'totp-setup');
  } catch (e) {
    logSkip('totp-setup', `dialog did not render (already enabled?): ${e.message}`);
    test.skip();
    return;
  }
  await page.keyboard.press('Escape');
});

// --- Settings ---

test('29. settings-panel.png', async ({ page }) => {
  await page.goto('/settings');
  await waitForSettled(page);
  await page.waitForTimeout(500);
  await shotFullScroll(page, 'settings-panel');
});

test('30. settings-dns-providers.png', async ({ page }) => {
  await page.goto('/settings');
  await waitForSettled(page);
  try {
    const dns = page.locator('h2, h3').filter({ hasText: /DNS providers?/i }).first();
    await dns.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(400);
  await shotFull(page, 'settings-dns-providers');
});

// --- Country bans (under Settings) ---

test('31. country-bans-progress.png (demo-only; skip in prod)', async ({ page }) => {
  if (isProd()) {
    logSkip('country-bans-progress', 'state-changing in prod (triggers real expansion); capture against demo');
    test.skip();
    return;
  }
  await page.goto('/settings');
  await waitForSettled(page);
  try {
    const cb = page.locator('h2, h3').filter({ hasText: /country ban/i }).first();
    await cb.scrollIntoViewIfNeeded({ timeout: 3_000 });
  } catch { /* tolerate */ }
  await page.waitForTimeout(400);
  await shotFull(page, 'country-bans-progress');
});

// Final hook: emit a real summary block (v1.3.36's `$(wc -l ...)` was
// a JS template string with bash command-substitution syntax that
// never expanded; the literal text appeared in stdout).
test.afterAll(async () => {
  const captured = fs.readdirSync(OUTPUT_DIR)
    .filter((f) => f.endsWith('.png'))
    .sort();
  let skippedCount = 0;
  try {
    skippedCount = fs.readFileSync(SKIP_LIST_PATH, 'utf8')
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .length;
  } catch { /* file missing -> 0 */ }
  // eslint-disable-next-line no-console
  console.log('');
  // eslint-disable-next-line no-console
  console.log(`==========================================`);
  // eslint-disable-next-line no-console
  console.log(`mode=${MODE}  output=${OUTPUT_DIR}`);
  // eslint-disable-next-line no-console
  console.log(`captures=${captured.length}`);
  // eslint-disable-next-line no-console
  console.log(`skipped=${skippedCount}`);
  // eslint-disable-next-line no-console
  console.log(`==========================================`);
});
