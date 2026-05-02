// Auth flow for the capture session. The ONLY place where raw
// page.click / page.fill are used (login is by definition a
// state-changing action -- creating a session); after login, every
// capture uses safeClick / safeHover / safeFill from lib/safe-page.js.

const { expect } = require('@playwright/test');

/**
 * loginToPanel: navigate to /login, fill credentials from env, click
 * Sign in, wait for /dashboard or /. Cookie persists across the rest
 * of the test run via the shared browser context.
 *
 * @param {import('@playwright/test').Page} page
 */
async function loginToPanel(page) {
  const url = process.env.ARGOS_PROD_URL;
  const user = process.env.ARGOS_PROD_USER;
  const pass = process.env.ARGOS_PROD_PASS;
  if (!url) throw new Error('ARGOS_PROD_URL not set in env -- copy .env.example to .env');
  if (!user) throw new Error('ARGOS_PROD_USER not set in env');
  if (!pass) throw new Error('ARGOS_PROD_PASS not set in env');

  await page.goto('/login');
  await page.waitForSelector('input[type="text"], input[name="username"]', { timeout: 10_000 });
  // Username + password fields are typed inputs; Playwright's "fill"
  // is the right action here. We bypass safeFill deliberately -- the
  // login form is the one place a fill IS authorized.
  await page.fill('input[name="username"], input[type="text"]', user);
  await page.fill('input[name="password"], input[type="password"]', pass);

  // Submit. The login button typically reads "Sign in" which the
  // safeClick allowlist would NOT block (it's in the login flow's
  // privileged scope), but use raw click here for clarity.
  await Promise.all([
    page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15_000 }),
    page.click('button[type="submit"]'),
  ]);

  // Sanity: after login we should NOT be on /login anymore.
  await expect(page).not.toHaveURL(/\/login(\?|$)/);
}

module.exports = { loginToPanel };
