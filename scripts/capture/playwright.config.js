// Playwright config for argos panel capture session.
//
// v1.3.36.1 changes (vs v1.3.36):
//   1. Two projects: 'setup' (runs auth.setup.js to persist cookies)
//      and 'captures' (runs capture.spec.js with the persisted
//      storageState). 'captures' depends on 'setup' so the auth runs
//      once at the start. This fixes the v1.3.36 first-run bug where
//      every post-login capture was silently a /login redirect.
//   2. Viewport bumped 1440x900 -> 1440x1080 so above-fold cards
//      have more room before scroll. Surfaces with long lists use
//      fullPage:true via shotFullScroll() (see capture.spec.js).
//
// Other settings unchanged:
//   - Single chromium project; no firefox/webkit.
//   - Dark mode forced via colorScheme: prefers-color-scheme media query.
//   - NO video, NO trace, NO screenshot-on-failure: privacy.
//   - retries: 0 because a flake is operator-visible.
//   - workers: 1 so the auth state + browser context is shared and
//     captures run sequentially in a predictable navigation order.

const { devices } = require('@playwright/test');

const AUTH_STATE = process.env.ARGOS_AUTH_STATE || '/tmp/argos-auth-state.json';

module.exports = {
  testDir: '.',
  timeout: 30_000,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: process.env.ARGOS_PROD_URL,
    viewport: { width: 1440, height: 1080 },
    colorScheme: 'dark',
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    ignoreHTTPSErrors: false,
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
  },
  projects: [
    {
      name: 'setup',
      testMatch: /auth\.setup\.js/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'captures',
      testMatch: /capture\.spec\.js/,
      dependencies: ['setup'],
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'dark',
        // Default storageState for every test in this project. The
        // login.png capture overrides this to {} (anon) per-test
        // so it can capture the un-authenticated /login page.
        storageState: AUTH_STATE,
      },
    },
  ],
};
