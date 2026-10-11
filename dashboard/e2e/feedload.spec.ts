// The event feed loads its history once on a first visit (fix plan step
// 7f). Before, it loaded at mount and again when the live feed connected.
//
// Same environment as smoke.spec.ts (HOOKMON_E2E_URL, HOOKMON_E2E_CA,
// HOOKMON_E2E_TOKEN); without it the test skips.

import { test, expect, chromium } from '@playwright/test';
import type { Browser } from '@playwright/test';
import fs from 'node:fs';
import tls from 'node:tls';
import crypto from 'node:crypto';

const BASE = process.env.HOOKMON_E2E_URL || '';
const CA_FILE = process.env.HOOKMON_E2E_CA || '';
const TOKEN = process.env.HOOKMON_E2E_TOKEN || '';
const CONFIGURED = !!(BASE && CA_FILE && TOKEN);

test.skip(!CONFIGURED, 'set HOOKMON_E2E_URL, HOOKMON_E2E_CA and HOOKMON_E2E_TOKEN to run against a hookmon-server');

let browser: Browser;

/** The server key's SHA-256, once Node has verified its certificate against the CA. */
function robServerKey(ca: Buffer): Promise<string> {
  const url = new URL(BASE);
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host: url.hostname, port: Number(url.port) || 443, ca, servername: url.hostname }, () => {
      const der = sock.getPeerX509Certificate()!.publicKey.export({ type: 'spki', format: 'der' });
      sock.end();
      resolve(crypto.createHash('sha256').update(der).digest('base64'));
    });
    sock.on('error', reject);
  });
}

test.beforeAll(async () => {
  if (!CONFIGURED) return;
  const spki = await robServerKey(fs.readFileSync(CA_FILE));
  browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${spki}`] });
});

test.afterAll(async () => {
  await browser?.close();
});

test('the event feed loads its history once on first load', async () => {
  const ctx = await browser.newContext({ baseURL: BASE });
  await ctx.addInitScript((t) => window.localStorage.setItem('hookmon_api_token', t), TOKEN);
  const page = await ctx.newPage();
  const history: string[] = [];
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (u.pathname === '/api/v1/events' && u.searchParams.get('limit') === '200') history.push(r.url());
  });

  await page.goto('/events');
  await expect(page.getByTestId('ws-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
  await expect(page.getByTestId('event-row').first()).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(3_000);
  console.log(`history requests on first load: ${history.length}`);
  expect(history, 'GET /api/v1/events?limit=200 on first load').toHaveLength(1);
  await ctx.close();
});
