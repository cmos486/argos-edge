// Setup project: logs into the panel once at the start of the run
// and persists the resulting cookie + origin storage to a state file
// that the 'captures' project reads via its `storageState` config.
//
// Without this, every test gets a fresh BrowserContext (Playwright's
// default per-test fixture behaviour) and the post-login tests
// silently capture redirected /login pages -- visible as test pass +
// wrong screenshot content (the v1.3.36 first-run regression).
//
// The state file lives at /tmp/argos-auth-state.json (or the path
// in ARGOS_AUTH_STATE if overridden). The wrapper scripts (run.sh,
// run-demo.sh) clean it up on exit via trap.

const { test, expect } = require('@playwright/test');
const { loginToPanel } = require('./lib/auth');

const AUTH_STATE = process.env.ARGOS_AUTH_STATE || '/tmp/argos-auth-state.json';

test('authenticate', async ({ page, context }) => {
  await loginToPanel(page);
  // Sanity: we're past /login.
  await expect(page).not.toHaveURL(/\/login(\?|$)/);
  // Persist cookies + storage to the file the captures project will
  // load via use.storageState.
  await context.storageState({ path: AUTH_STATE });
});
