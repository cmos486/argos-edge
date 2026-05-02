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
 *   - "Create" / "Create target group" buttons — open a client-side
 *     form modal; the API call only fires on the modal's own
 *     onSubmit handler (which we never trigger).
 *   - Row-click on a host/target-group listing — opens edit modal.
 *
 * Misuse is obvious at the call site (`openModal` name vs `safeClick`).
 * Spec authors must NOT use this for buttons that submit on click
 * (the panel currently has no such buttons in our auto-capture set;
 * audit before adding new ones).
 */
async function openModal(page, selector, reason) {
  if (!reason) {
    throw new Error(`[openModal] requires a reason string -- audit log for the override`);
  }
  const handle = await page.waitForSelector(selector, { state: 'visible', timeout: 10_000 });
  await handle.click();
  // Console log so the stdout transcript shows every block-bypass.
  // eslint-disable-next-line no-console
  console.log(`[openModal] override: selector="${selector}" reason="${reason}"`);
}

module.exports = { safeClick, safeHover, safeFill, openModal, looksBlocked };
