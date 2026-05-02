// Playwright config for argos panel capture session.
//
// Settings chosen for screenshot fidelity + privacy:
//
//   - Single chromium project; no firefox/webkit (we only ship one
//     browser-rendered theme into the docs portal anyway).
//   - 1440x900 viewport: matches the docs portal's wide-content
//     break and the panel's dashboard grid layout.
//   - Dark mode forced via colorScheme: prefers-color-scheme media
//     query is what the panel reads to switch palettes.
//   - NO video, NO trace, NO screenshot-on-failure: this session
//     is operator-mediated against prod; recording runtime data
//     would leak operator info.
//   - retries: 0 because a flake is operator-visible; rerun once
//     manually instead of accumulating noisy artifacts.
//   - workers: 1 so login state + browser context is shared and
//     captures run sequentially in a predictable navigation order.
//   - timeout per test: 30s (panel responses are sub-second; if
//     a capture stalls past 30s, the surface is broken or the
//     network is hostile).

const { devices } = require('@playwright/test');

module.exports = {
  testDir: '.',
  testMatch: /.*\.spec\.js/,
  timeout: 30_000,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL: process.env.ARGOS_PROD_URL,
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    ignoreHTTPSErrors: false, // prod has a real cert; LAN trial cert flow uses staging CA which we don't capture against here
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
  ],
};
