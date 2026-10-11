import { defineConfig } from '@playwright/test';

// Smoke tests of the built dashboard against a running, seeded
// hookmon-server. They skip unless HOOKMON_E2E_URL, HOOKMON_E2E_CA and
// HOOKMON_E2E_TOKEN are set; see e2e/smoke.spec.ts.
export default defineConfig({
  testDir: './e2e',
  timeout: 240_000,
  workers: 1,
  reporter: [['list']],
});
