// Read-only enforcement wrapper for Playwright page interactions.
//
// Every capture spec uses these helpers instead of the raw page.click /
// page.fill methods. Click targets are inspected and refused when
// their visible text matches the blocked-action regex; this is a
// belt-and-suspenders defence on top of the spec author's discipline.
// A buggy spec that tries to click "Save" or "Delete" or "Apply" will
// fail loudly here rather than mutating production state.
//
// page.fill is allowed only when the test has marked the field as
// authorized (typically only the login form). All other fills are
// refused -- there's no read-only screenshot that needs to type into
// a field, and a fill of a misroute'd selector is a real risk.
//
// The login flow uses raw page.click / page.fill via lib/auth.js;
// after login completes, the spec switches to safeClick / safeHover
// for everything else.

const BLOCKED_TEXT_PATTERNS = [
  /^Save\b/i,
  /^Add\b/i,
  /^Delete\b/i,
  /^Remove\b/i,
  /^Apply\b/i,
  /^Confirm\b/i,
  /^Submit\b/i,
  /^Create\b/i,
  /^Run\b/i,
  /^Trigger\b/i,
  /^Restart\b/i,
  /^Reset\b/i,
  /^Send\b/i,
  /^Send test\b/i,
  /^Disable\b/i,
  /^Enable\b/i,
  /^Generate\b/i,
  /^Regenerate\b/i,
  /^Revoke\b/i,
  /^Ban\b/i,
  /^Unban\b/i,
  /^Whitelist\b/i,
  /^Purge\b/i,
  /^Refresh\b/i,         // calls /api/.../refresh which mutates state
  /^Mark applied\b/i,
  /^Sign out\b/i,
  /^Logout\b/i,
];

function looksBlocked(text) {
  if (!text) return false;
  const trimmed = text.trim();
  return BLOCKED_TEXT_PATTERNS.some((p) => p.test(trimmed));
}

/**
 * safeClick: click a selector ONLY after asserting the target's
 * visible text is not in the blocked-action set. Throws (which
 * Playwright surfaces as a test failure) on a blocked match.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} selector
 */
async function safeClick(page, selector) {
  const handle = await page.waitForSelector(selector, { state: 'visible', timeout: 10_000 });
  const text = (await handle.textContent()) || '';
  if (looksBlocked(text)) {
    throw new Error(
      `[safeClick] BLOCKED: selector="${selector}" text="${text.trim()}" matches a state-changing action. ` +
      `Capture sessions are read-only against production. If this click is genuinely safe, audit the ` +
      `BLOCKED_TEXT_PATTERNS list in lib/safe-page.js.`,
    );
  }
  await handle.click();
}

/**
 * safeHover: same protection but for hover (e.g. surfacing tooltips).
 * Hovers don't mutate state but the same allowlist sanity-check is
 * cheap insurance.
 */
async function safeHover(page, selector) {
  const handle = await page.waitForSelector(selector, { state: 'visible', timeout: 10_000 });
  const text = (await handle.textContent()) || '';
  if (looksBlocked(text)) {
    throw new Error(`[safeHover] BLOCKED: selector="${selector}" text="${text.trim()}"`);
  }
  await handle.hover();
}

/**
 * safeFill is intentionally a no-op shim that THROWS unless the test
 * has explicitly opted-in via the AUTHORIZED_FILL flag (used only by
 * lib/auth.js for the login form).
 */
async function safeFill(_page, _selector, _value) {
  throw new Error(
    `[safeFill] BLOCKED: capture sessions don't fill form fields outside the auth flow. ` +
    `If you need a state-changing capture, do it manually -- the script's read-only contract ` +
    `forbids form mutation against production.`,
  );
}

/**
 * openModal: explicit escape hatch for click targets whose visible
 * text would match the safeClick blocklist BUT that the spec author
 * has audited as opening-a-modal-without-immediate-submit.
 *
 * Audited safe cases:
 *   - "Add target group" / "Create" buttons — open a client-side
 *     form modal; the API call only fires on the modal's own
 *     onSubmit handler (which we never trigger).
 *   - Row-click on a host/target-group listing — opens edit modal.
 *   - "Enable" button on /system → opens TOTP enrollment dialog
 *     (demo only).
 *   - Form-state changes inside an already-open modal (e.g.
 *     selecting the DNS-01 radio) — no modal-open wait needed,
 *     pass `modalSelector=null`.
 *
 * Misuse is obvious at the call site (`openModal` name vs `safeClick`).
 * Spec authors must NOT use this for buttons that submit on click.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} triggerSelector  the element to click
 * @param {string} reason           human-readable audit log entry
 * @param {string|null} modalSelector  if provided, wait for this
 *   selector to be visible after the click (modal-open path) and
 *   apply a 400ms animation-settle delay before returning. Pass
 *   null/undefined for clicks that DON'T open a new modal (e.g.
 *   form-state changes inside an existing modal).
 */
async function openModal(page, triggerSelector, reason, modalSelector = null) {
  if (!reason) {
    throw new Error(`[openModal] requires a reason string -- audit log for the override`);
  }
  const handle = await page.waitForSelector(triggerSelector, { state: 'visible', timeout: 10_000 });
  await handle.click();
  if (modalSelector) {
    // v1.3.36.3 modal-timing fix: pre-this-arg, openModal returned
    // immediately after the click, so screenshots fired mid-modal-
    // animation (modal not visible yet OR partly faded in). Wait for
    // explicit visibility + an animation-settle delay matching the
    // typical 200-400ms framer-motion / CSS transition duration.
    await page.waitForSelector(modalSelector, { state: 'visible', timeout: 5_000 });
    await page.waitForTimeout(400);
  }
  // Console log so the stdout transcript shows every block-bypass.
  // eslint-disable-next-line no-console
  console.log(
    `[openModal] override: trigger="${triggerSelector}" reason="${reason}"` +
    (modalSelector ? ` modal="${modalSelector}"` : ''),
  );
}

/**
 * safeClickTab: explicit escape hatch for tab navigation clicks
 * whose visible text might match the safeClick blocklist (e.g. a
 * "Whitelist" tab whose label collides with the "Whitelist this
 * IP" verb action). Tab clicks change view URL / local component
 * state — they don't mutate server-side state — so the blocklist
 * is a false positive for them.
 *
 * v1.3.36.5: introduced after `security-whitelist.png` capture
 * failed because the Whitelist tab's button text "Whitelist"
 * tripped /^Whitelist\b/i. Other tab clicks (Activity, Scenarios,
 * AppSec, Metrics, Deliveries) didn't trip currently but migrate
 * here for consistency + future-proofing against new tab labels
 * that might collide (e.g. "Disabled", "Reset", "Enable").
 *
 * Misuse is obvious at the call site (`safeClickTab` name vs
 * `safeClick`). Spec authors must NOT use this for state-changing
 * action buttons that happen to live near tab strips — only for
 * actual tab navigation.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} selector
 * @param {string} reason  human-readable audit log entry
 */
async function safeClickTab(page, selector, reason) {
  if (!reason) {
    throw new Error(`[safeClickTab] requires a reason string -- audit log for the override`);
  }
  const handle = await page.waitForSelector(selector, { state: 'visible', timeout: 10_000 });
  await handle.click();
  // eslint-disable-next-line no-console
  console.log(`[safeClickTab] override: selector="${selector}" reason="${reason}"`);
}

module.exports = { safeClick, safeHover, safeFill, openModal, safeClickTab, looksBlocked };
