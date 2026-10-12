// Smoke test of the dashboard against a real, seeded hookmon-server (fix
// plan step 7e). It opens every page and checks each shows the data the
// API holds, exercises "Allowlist this event" and the enable toggle, and
// checks that two tabs both receive every live event.
//
// Environment:
//   HOOKMON_E2E_URL    the server's dashboard URL, e.g. https://hookmon.internal:8443
//   HOOKMON_E2E_CA     the CA certificate that signed the server certificate
//   HOOKMON_E2E_TOKEN  an API token (api.tokens)
//   HOOKMON_E2E_MIN_LIVE_EVENTS  live events both tabs must see (default 10);
//                      something on a monitored host must be producing events
//
// Without the first three every test skips, so `npx playwright test` in CI
// passes without a server. The server's certificate is verified against
// HOOKMON_E2E_CA in Node; the browser then trusts only that certificate's
// key (--ignore-certificate-errors-spki-list), never any certificate.

import { test, expect, chromium } from '@playwright/test';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import fs from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import crypto from 'node:crypto';

const BASE = process.env.HOOKMON_E2E_URL || '';
const CA_FILE = process.env.HOOKMON_E2E_CA || '';
const TOKEN = process.env.HOOKMON_E2E_TOKEN || '';
const MIN_LIVE = Number(process.env.HOOKMON_E2E_MIN_LIVE_EVENTS || '10');
const CONFIGURED = !!(BASE && CA_FILE && TOKEN);

test.skip(!CONFIGURED, 'set HOOKMON_E2E_URL, HOOKMON_E2E_CA and HOOKMON_E2E_TOKEN to run against a seeded hookmon-server');

// The API shapes these tests read (see src/api/types.ts).
interface Evt {
  id: string;
  hostname: string;
  host_id: string;
  event_type: string;
  bpf_detail?: { prog_hash: string };
  policy_result?: { action: string };
}
interface Entry {
  id: string;
  action: string;
  enabled: boolean;
  description: string;
  learned?: { exe_path?: string; key: { subject?: string } };
}
interface HostRow {
  id: string;
  hostname: string;
  sensors?: { name: string; status: string }[];
}
interface Settings {
  grpc_addr: string;
  enroll_addr: string;
  http_addr: string;
  connectors: { name: string; sent: number }[];
  enrollment: { enabled: boolean; tokens: { name: string }[] };
}

let ca: Buffer;
let browser: Browser;

/** An authenticated API call over TLS, verified against the CA. */
function api<T>(method: string, path: string, body?: unknown): Promise<{ status: number; data: T }> {
  const url = new URL(path, BASE);
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      { method, ca, headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' } },
      (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (buf += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, data: (buf ? JSON.parse(buf) : undefined) as T }));
      }
    );
    req.on('error', reject);
    if (body !== undefined) req.write(JSON.stringify(body));
    req.end();
  });
}

async function apiGet<T>(path: string): Promise<T> {
  const res = await api<T>('GET', path);
  expect(res.status, `GET ${path}`).toBe(200);
  return res.data;
}

/**
 * The SHA-256 of the server certificate's public key, after Node has
 * verified the certificate against the CA and the host name.
 */
function verifiedServerKey(): Promise<string> {
  const url = new URL(BASE);
  return new Promise((resolve, reject) => {
    const sock = tls.connect(
      { host: url.hostname, port: Number(url.port) || 443, ca, servername: url.hostname },
      () => {
        const der = sock.getPeerX509Certificate()!.publicKey.export({ type: 'spki', format: 'der' });
        sock.end();
        resolve(crypto.createHash('sha256').update(der).digest('base64'));
      }
    );
    sock.on('error', reject);
  });
}

function port(addr: string): string {
  return addr.slice(addr.lastIndexOf(':') + 1);
}

test.beforeAll(async () => {
  if (!CONFIGURED) return;
  ca = fs.readFileSync(CA_FILE);
  const spki = await verifiedServerKey();
  browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${spki}`] });
});

test.afterAll(async () => {
  await browser?.close();
});

async function newContext(): Promise<BrowserContext> {
  const ctx = await browser.newContext({ baseURL: BASE });
  ctx.setDefaultTimeout(20_000);
  await ctx.addInitScript((t) => window.localStorage.setItem('hookmon_api_token', t), TOKEN);
  return ctx;
}

async function nav(page: Page, name: RegExp) {
  await page.getByRole('link', { name }).click();
}

test('every page renders the server data', async () => {
  const ctx = await newContext();
  const page = await ctx.newPage();
  const pageErrors: string[] = [];
  page.on('pageerror', (e) => pageErrors.push(String(e)));

  // Event feed: the newest stored event is a row, and the live feed is up.
  const events = await apiGet<Evt[]>('/api/v1/events?limit=200');
  expect(events.length).toBeGreaterThan(0);
  await page.goto('/events');
  await expect(page.getByTestId('ws-status')).toHaveAttribute('data-state', 'live');
  await expect(page.locator(`[data-testid=event-row][data-event-id="${events[0].id}"]`)).toBeVisible();
  console.log(`Events: ${await page.getByTestId('event-row').count()} rows; newest ${events[0].event_type} ${events[0].id} from ${events[0].hostname}`);

  // Investigation, opened from the feed.
  const pick = events[Math.min(5, events.length - 1)];
  await page.locator(`[data-testid=event-row][data-event-id="${pick.id}"]`).click();
  await expect(page).toHaveURL(new RegExp(`/events/${pick.id}$`));
  await expect(page.getByTestId('event-id')).toContainText(pick.id);
  await expect(page.getByRole('heading', { name: 'Event Investigation' })).toBeVisible();
  await expect(page.getByText(pick.event_type).first()).toBeVisible();
  console.log(`Investigation: ${pick.event_type} ${pick.id}, opened from the feed`);

  // A BPF event, if the server has one, shows its program tag.
  const bpf = (await apiGet<Evt[]>('/api/v1/events?event_type=BPF_INVENTORY&limit=50')).find((e) => e.bpf_detail?.prog_hash);
  if (bpf) {
    await page.goto(`/events/${bpf.id}`);
    await expect(page.getByTestId('bpf-tag')).toHaveText(bpf.bpf_detail!.prog_hash);
    console.log(`Investigation: BPF_INVENTORY ${bpf.id}, tag ${bpf.bpf_detail!.prog_hash}`);
  }

  // "Allowlist this event" from Investigation, for its host. The entry it
  // creates is deleted again afterwards.
  const unallowed = events.find(
    (e) => e.policy_result && e.policy_result.action !== 'ALLOW' && !e.event_type.startsWith('AGENT_') && e.host_id
  );
  if (unallowed) {
    await page.goto(`/events/${unallowed.id}`);
    await page.getByRole('button', { name: 'Allowlist' }).click();
    await page.getByLabel(/This host only/).check();
    await page.getByRole('button', { name: 'Create ALLOW entry' }).click();
    const created = page.getByTestId('allowlist-created');
    await expect(created).toBeVisible();
    const text = await created.innerText();
    const id = /entry ([0-9a-f-]{36})/.exec(text)?.[1];
    expect(id, text).toBeTruthy();
    const entries = await apiGet<(Entry & { host_id?: string })[]>('/api/v1/policies');
    const made = entries.find((e) => e.id === id);
    expect(made?.host_id).toBe(unallowed.host_id);
    expect(made?.action).toBe('ALLOW');
    expect(made?.learned).toBeTruthy();
    console.log(`Allowlisted ${unallowed.event_type} ${unallowed.id} for host ${unallowed.hostname}: ${made?.description}`);
    expect((await api('DELETE', `/api/v1/policies/${id}`)).status).toBe(204);
    await page.getByRole('button', { name: 'Done' }).click();
  } else {
    console.log('No unallowed hook event to allowlist; skipped that step');
  }

  // Hosts: each enrolled host, with its sensors from the last heartbeat.
  const hosts = await apiGet<HostRow[]>('/api/v1/hosts');
  expect(hosts.length).toBeGreaterThan(0);
  await nav(page, /Hosts/);
  for (const h of hosts) {
    const card = page.locator(`[data-testid=host-card][data-host-id="${h.id}"]`);
    await expect(card).toContainText(h.hostname);
    const sensors = h.sensors || [];
    await expect(card.getByTestId('sensor')).toHaveCount(sensors.length);
    if (sensors.length) {
      const alive = sensors.filter((s) => s.status === 'alive').length;
      await expect(card).toContainText(`Sensors: ${alive} of ${sensors.length} alive`);
    }
    console.log(`Hosts: ${h.hostname} (${h.id}), sensors ${sensors.map((s) => `${s.name}=${s.status}`).join(' ')}`);
  }

  // Policies: every entry in force; the enable toggle round-trips. A fresh
  // server (the compose appliance, say) has no entries yet, so make one
  // that matches nothing and delete it when the step is done.
  let seeded: string | undefined;
  if ((await apiGet<Entry[]>('/api/v1/policies')).length === 0) {
    const res = await api<Entry>('POST', '/api/v1/policies', {
      description: 'smoke test: temporary entry',
      event_types: ['BPF_LOAD'],
      exe_path: '/nonexistent/hookmon-smoke-test',
      action: 'ALERT',
      enabled: true,
    });
    expect(res.status, 'POST /api/v1/policies').toBe(201);
    seeded = res.data.id;
  }
  try {
  const policies = await apiGet<Entry[]>('/api/v1/policies');
  expect(policies.length).toBeGreaterThan(0);
  await nav(page, /Policies/);
  await expect(page.getByTestId('policy-row')).toHaveCount(policies.length);
  const first = policies[0];
  const row = page.locator(`[data-testid=policy-row][data-entry-id="${first.id}"]`);
  await expect(row).toContainText(first.description || '(no description)');
  await expect(row).toContainText(first.action);
  await row.locator('label.toggle').click();
  await expect.poll(async () => (await apiGet<Entry[]>('/api/v1/policies')).find((e) => e.id === first.id)?.enabled).toBe(!first.enabled);
  await row.locator('label.toggle').click();
  await expect.poll(async () => (await apiGet<Entry[]>('/api/v1/policies')).find((e) => e.id === first.id)?.enabled).toBe(first.enabled);
  console.log(`Policies: ${policies.length} rows; toggled "${first.description}" off and on`);
  } finally {
    if (seeded) {
      const res = await api('DELETE', `/api/v1/policies/${seeded}`);
      expect([200, 204], 'DELETE the temporary entry').toContain(res.status);
    }
  }

  // New hooks: every PENDING entry, with the bulk controls. Nothing is
  // decided here: the decisions are covered against a mock (newhooks.spec.ts).
  const pending = await apiGet<Entry[]>('/api/v1/policies?status=PENDING');
  await nav(page, /New hooks/);
  if (pending.length === 0) {
    await expect(page.getByTestId('new-hooks-empty')).toBeVisible();
    console.log('New hooks: none');
  } else {
    await expect(page.getByTestId('hook-row')).toHaveCount(pending.length);
    // The count was read when the app loaded; a live bus can add hooks since.
    await expect(page.getByTestId('new-hooks-count')).toHaveText(/^\d+$/);
    const p0 = page.locator(`[data-testid=hook-row][data-entry-id="${pending[0].id}"]`);
    if (pending[0].learned?.exe_path) {
      await expect(p0).toContainText(pending[0].learned.exe_path);
    }
    await p0.getByTestId('hook-select').check();
    await expect(page.getByTestId('selected-count')).toHaveText('1 selected');
    await expect(page.getByRole('button', { name: 'Allow — ignore in future' })).toBeEnabled();
    await p0.getByTestId('hook-select').uncheck();
    console.log(`New hooks: ${pending.length} rows; first ${pending[0].description}`);
  }

  // Settings: the enrollment command with the server's real ports, and
  // the connectors' counts.
  const st = await apiGet<Settings>('/api/v1/settings');
  await nav(page, /Settings/);
  const host = new URL(BASE).hostname;
  const cmd = page.getByTestId('enroll-command');
  await expect(cmd).toContainText('--enroll-token-file /etc/hookmon/enroll-token');
  await expect(cmd).toContainText(`--server-addr ${host}:${port(st.grpc_addr)}`);
  await expect(cmd).toContainText(`--enroll-addr ${host}:${port(st.enroll_addr)}`);
  await expect(cmd).toContainText('--ca-file');
  await expect(cmd).toContainText('--state-dir /var/lib/hookmon');
  await expect(page.getByTestId('server-ports')).toContainText(st.http_addr);
  for (const t of st.enrollment.tokens) {
    await expect(page.getByRole('cell', { name: t.name, exact: true })).toBeVisible();
  }
  if (st.connectors.length) {
    for (const c of st.connectors) {
      await expect(page.getByTestId('connectors')).toContainText(c.name);
    }
  } else {
    await expect(page.getByTestId('connectors-none')).toBeVisible();
  }
  console.log(`Settings: ${(await cmd.innerText()).replace(/\s*\\\n\s*/g, ' ')}; connectors ${st.connectors.map((c) => `${c.name} sent=${c.sent}`).join(', ') || 'none'}`);

  expect(pageErrors).toEqual([]);
  await ctx.close();
});

test('two tabs both receive every live event', async () => {
  const ctx = await newContext();
  const tabs = [await ctx.newPage(), await ctx.newPage()];
  const seen: string[][] = [[], []];
  tabs.forEach((p, i) => {
    p.on('websocket', (ws) => {
      if (!ws.url().endsWith('/api/v1/ws/events')) return;
      ws.on('framereceived', (f) => {
        try {
          seen[i].push(JSON.parse(String(f.payload)).id);
        } catch {
          // not an event
        }
      });
    });
  });
  for (const p of tabs) {
    await p.goto('/events');
    await expect(p.getByTestId('ws-status')).toHaveAttribute('data-state', 'live');
  }

  await expect
    .poll(() => Math.min(seen[0].length, seen[1].length), { timeout: 180_000, message: 'live events in both tabs' })
    .toBeGreaterThanOrEqual(MIN_LIVE);

  // The tab that connected later starts somewhere in the other's stream;
  // from there the two must be identical. Poll, since an event can be in
  // flight to one tab and not yet the other.
  const compare = () => {
    for (const [early, late] of [
      [seen[0], seen[1]],
      [seen[1], seen[0]],
    ]) {
      const i = early.indexOf(late[0]);
      if (i < 0) continue;
      const tail = early.slice(i);
      return JSON.stringify(tail) === JSON.stringify(late)
        ? `equal (${late.length} events)`
        : `differ: ${tail.length} vs ${late.length}`;
    }
    return 'no common first event';
  };
  await expect.poll(compare, { timeout: 30_000, intervals: [100] }).toMatch(/^equal/);
  console.log(`Two tabs: tab 1 saw ${seen[0].length} live events, tab 2 saw ${seen[1].length}; ${compare()} from the later tab's first event`);

  // Both tabs render the latest common event as a row.
  const common = seen[0].filter((id) => seen[1].includes(id));
  const last = common[common.length - 1];
  for (const p of tabs) {
    await expect(p.locator(`[data-testid=event-row][data-event-id="${last}"]`)).toBeVisible();
  }
  await ctx.close();
});
