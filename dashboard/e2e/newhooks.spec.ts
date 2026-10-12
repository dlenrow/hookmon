// The New hooks page against a mocked API: no server needed. The built
// dashboard is served by `vite preview`, and every /api/v1 request and the
// live WebSocket are answered in the browser (page.route and
// page.routeWebSocket), from a small in-memory model of the server's
// PENDING entries and POST /api/v1/policies/decide.
//
// NEWHOOKS_SCREENSHOT_DIR, if set, receives screenshots of the page.

import { test, expect } from '@playwright/test';
import type { Page, WebSocketRoute } from '@playwright/test';
import { build, preview } from 'vite';
import type { PreviewServer } from 'vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHOTS = process.env.NEWHOOKS_SCREENSHOT_DIR || '';

let server: PreviewServer;
let baseURL = '';

test.beforeAll(async () => {
  await build({ root, logLevel: 'warn' });
  server = await preview({ root, logLevel: 'warn', preview: { host: '127.0.0.1', port: 4317, strictPort: false } });
  baseURL = server.resolvedUrls!.local[0].replace(/\/$/, '');
});

test.afterAll(async () => {
  await server?.close();
});

interface Entry {
  id: string;
  created_at: string;
  created_by: string;
  description: string;
  event_types: string[];
  action: string;
  enabled: boolean;
  status: string;
  learned: {
    key: { event_type: string; exe_hash: string; subject_kind?: string; subject?: string; prog_type?: number; in_container: boolean };
    exe_path: string;
    occurrences: number;
    first_seen: string;
    last_seen: string;
    hosts: string[];
    first_event_id: string;
  };
}

const HOSTS = [
  { id: 'host-a', hostname: 'web-01', status: 'ONLINE' },
  { id: 'host-b', hostname: 'web-02', status: 'ONLINE' },
];

function iso(msAgo: number): string {
  return new Date(Date.now() - msAgo).toISOString();
}

const MIN = 60_000;
const DAY = 24 * 60 * MIN;

function entry(
  id: string,
  type: string,
  exe: string,
  subject: { kind: string; value: string; progType?: number },
  firstAgo: number,
  hosts: string[]
): Entry {
  return {
    id,
    created_at: iso(firstAgo),
    created_by: 'learning',
    description: `${type} ${subject.value} by ${exe}`,
    event_types: [type],
    action: 'ALERT',
    enabled: true,
    status: 'PENDING',
    learned: {
      key: {
        event_type: type,
        exe_hash: `sha256:${id.padEnd(64, '0')}`,
        subject_kind: subject.kind,
        subject: subject.value,
        prog_type: subject.progType,
        in_container: false,
      },
      exe_path: exe,
      occurrences: 3,
      first_seen: iso(firstAgo),
      last_seen: iso(MIN),
      hosts,
      first_event_id: `evt-${id}`,
    },
  };
}

/**
 * Two batches: a software update two days ago (four hooks within three
 * minutes, on both hosts) and two unrelated hooks an hour ago.
 */
function fixture(): Entry[] {
  return [
    entry('upd-1', 'BPF_LOAD', '/usr/bin/falco', { kind: 'bpf_tag', value: 'a04f5eef06a7f555', progType: 5 }, 2 * DAY, ['host-a', 'host-b']),
    entry('upd-2', 'BPF_LOAD', '/usr/bin/falco', { kind: 'bpf_tag', value: 'b14f5eef06a7f556', progType: 5 }, 2 * DAY - 1 * MIN, ['host-a', 'host-b']),
    entry('upd-3', 'BPF_LOAD', '/usr/bin/falco', { kind: 'bpf_tag', value: 'c24f5eef06a7f557', progType: 26 }, 2 * DAY - 2 * MIN, ['host-a', 'host-b']),
    entry('upd-4', 'DLOPEN', '/usr/bin/falco', { kind: 'library_hash', value: 'sha256:' + 'd'.repeat(64) }, 2 * DAY - 3 * MIN, ['host-a']),
    entry('new-1', 'PTRACE_INJECT', '/usr/bin/gdb', { kind: '', value: '' }, 60 * MIN, ['host-a']),
    entry('new-2', 'SHM_CREATE', '/tmp/.x/runtime', { kind: 'shm_pattern', value: 'bpftime' }, 58 * MIN, ['host-b']),
  ];
}

interface DecideBody {
  ids: string[];
  decision: string;
  scope: string;
}

interface Mock {
  pending: Entry[];
  decides: DecideBody[];
  /** IDs the server reports as no longer PENDING. */
  fail: Set<string>;
  sockets: WebSocketRoute[];
  events: unknown[];
}

async function mockServer(page: Page): Promise<Mock> {
  const m: Mock = { pending: fixture(), decides: [], fail: new Set(), sockets: [], events: [] };
  await page.addInitScript(() => window.localStorage.setItem('hookmon_api_token', 'test-token'));
  await page.routeWebSocket(/\/api\/v1\/ws\/events$/, (ws) => {
    m.sockets.push(ws);
  });
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    const p = url.pathname;
    if (req.method() === 'GET' && p === '/api/v1/policies' && url.searchParams.get('status') === 'PENDING') {
      return json(m.pending);
    }
    if (req.method() === 'GET' && p === '/api/v1/hosts') return json(HOSTS);
    if (req.method() === 'GET' && p === '/api/v1/learning') return json({ now: new Date().toISOString(), windows: [] });
    if (req.method() === 'GET' && p === '/api/v1/events') return json(m.events);
    if (req.method() === 'POST' && p === '/api/v1/policies/decide') {
      const body = req.postDataJSON() as DecideBody;
      m.decides.push(body);
      const results = body.ids.map((id) => {
        const e = m.pending.find((x) => x.id === id);
        if (!e || m.fail.has(id)) {
          return { id, ok: false, error: `allowlist entry ${id} is APPROVED: not PENDING` };
        }
        m.pending = m.pending.filter((x) => x.id !== id);
        return {
          id,
          ok: true,
          entries: (body.scope === 'fleet' ? [''] : e.learned.hosts).map((h) => ({
            ...e,
            id: `${id}-${h || 'fleet'}`,
            host_id: h,
            status: body.decision === 'approve' ? 'APPROVED' : 'REJECTED',
            action: body.decision === 'approve' ? 'ALLOW' : 'ALERT',
          })),
        };
      });
      return json({ results });
    }
    return json({ error: `not mocked: ${req.method()} ${p}` }, 404);
  });
  return m;
}

const rows = (page: Page) => page.getByTestId('hook-row');
const row = (page: Page, id: string) => page.locator(`[data-testid=hook-row][data-entry-id="${id}"]`);

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, name), fullPage: true });
}

test('an update batch: filter to its time, select all shown, allow for the fleet', async ({ page }) => {
  const m = await mockServer(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${baseURL}/new-hooks`);
  await expect(rows(page)).toHaveCount(6);
  await expect(page.getByTestId('new-hooks-count')).toHaveText('6');
  await expect(page.getByTestId('batch-row')).toHaveCount(2);
  // Newest first: the hour-old pair, then the update.
  await expect(rows(page).first()).toHaveAttribute('data-entry-id', 'new-2');
  await expect(row(page, 'upd-1').getByTestId('hook-evidence')).toHaveAttribute('href', '/events/evt-upd-1');
  await shot(page, 'new-hooks.png');

  // "Same time" on one of the update's hooks shows the whole update.
  await row(page, 'upd-3').getByTestId('same-time').click();
  await expect(rows(page)).toHaveCount(4);
  await expect(page.getByTestId('shown-count')).toHaveText('4 of 6 shown');
  await page.getByTestId('select-all-shown').check();
  await expect(page.getByTestId('selected-count')).toHaveText('4 selected');

  await page.getByRole('button', { name: 'Allow — ignore in future' }).click();
  const dialog = page.getByTestId('confirm-dialog');
  await expect(dialog).toContainText('Allow 4 new hooks for the whole fleet?');
  await expect(page.getByTestId('confirm-scope')).toHaveText('They will never alert again, on every host in the fleet.');
  await shot(page, 'new-hooks-confirm.png');
  await page.getByTestId('confirm-decision').click();

  await expect(page.getByTestId('decide-summary')).toContainText('Allowed 4 of 4 new hooks for the whole fleet.');
  expect(m.decides).toHaveLength(1);
  expect(m.decides[0].decision).toBe('approve');
  expect(m.decides[0].scope).toBe('fleet');
  expect([...m.decides[0].ids].sort()).toEqual(['upd-1', 'upd-2', 'upd-3', 'upd-4']);
  await expect(rows(page)).toHaveCount(0);
  await expect(page.getByTestId('new-hooks-count')).toHaveText('2');

  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(rows(page)).toHaveCount(2);
  await shot(page, 'new-hooks-after.png');
});

test('allow only on the hosts where each was seen', async ({ page }) => {
  const m = await mockServer(page);
  await page.goto(`${baseURL}/new-hooks`);
  await row(page, 'upd-1').getByTestId('hook-select').check();
  await row(page, 'upd-4').getByTestId('hook-select').check();
  await page.getByTestId('bulk-scope').selectOption('seen_hosts');
  await page.getByRole('button', { name: 'Allow — ignore in future' }).click();
  await expect(page.getByTestId('confirm-dialog')).toContainText('Allow 2 new hooks on the hosts where each was seen?');
  await expect(page.getByTestId('confirm-scope')).toContainText('only on the hosts where each was seen (2 hosts)');
  await page.getByTestId('confirm-decision').click();

  await expect(page.getByTestId('decide-summary')).toContainText('Allowed 2 of 2 new hooks on the hosts where each was seen.');
  expect(m.decides[0].decision).toBe('approve');
  expect(m.decides[0].scope).toBe('seen_hosts');
  expect([...m.decides[0].ids].sort()).toEqual(['upd-1', 'upd-4']);
  await expect(row(page, 'upd-1')).toHaveCount(0);
  await expect(row(page, 'upd-4')).toHaveCount(0);
  await expect(rows(page)).toHaveCount(4);
});

test('deny: the hook alerts every time', async ({ page }) => {
  const m = await mockServer(page);
  await page.goto(`${baseURL}/new-hooks`);
  await row(page, 'new-2').getByTestId('hook-select').check();
  await page.getByRole('button', { name: 'Deny — alert every time' }).click();
  await expect(page.getByTestId('confirm-dialog')).toContainText('Deny 1 new hook for the whole fleet?');
  await expect(page.getByTestId('confirm-scope')).toHaveText('Each will alert every time it happens again, on every host in the fleet.');
  await page.getByTestId('confirm-decision').click();

  await expect(page.getByTestId('decide-summary')).toContainText('Denied 1 of 1 new hook for the whole fleet.');
  expect(m.decides[0]).toEqual({ ids: ['new-2'], decision: 'reject', scope: 'fleet' });
  await expect(row(page, 'new-2')).toHaveCount(0);
  await expect(page.getByTestId('new-hooks-count')).toHaveText('5');
});

test('a partial failure is reported per hook, and the failed one stays selected', async ({ page }) => {
  const m = await mockServer(page);
  m.fail.add('upd-2');
  await page.goto(`${baseURL}/new-hooks`);
  for (const id of ['upd-1', 'upd-2', 'upd-3']) await row(page, id).getByTestId('hook-select').check();
  await page.getByRole('button', { name: 'Allow — ignore in future' }).click();
  await page.getByTestId('confirm-decision').click();

  const summary = page.getByTestId('decide-summary');
  await expect(summary).toContainText('Allowed 2 of 3 new hooks for the whole fleet. 1 failed and is still listed and selected:');
  const failure = page.getByTestId('decide-failure');
  await expect(failure).toHaveCount(1);
  await expect(failure).toHaveAttribute('data-entry-id', 'upd-2');
  await expect(failure).toContainText('allowlist entry upd-2 is APPROVED: not PENDING');
  await expect(row(page, 'upd-1')).toHaveCount(0);
  await expect(row(page, 'upd-3')).toHaveCount(0);
  await expect(row(page, 'upd-2')).toHaveCount(1);
  await expect(row(page, 'upd-2').getByTestId('hook-select')).toBeChecked();
  await expect(page.getByTestId('selected-count')).toHaveText('1 selected');
});

test('a decision never reaches a row hidden by the filters', async ({ page }) => {
  const m = await mockServer(page);
  await page.goto(`${baseURL}/new-hooks`);
  await page.getByTestId('select-all-shown').check();
  await expect(page.getByTestId('selected-count')).toHaveText('6 selected');
  await page.getByTestId('filter-type').selectOption('BPF_LOAD');
  await expect(rows(page)).toHaveCount(3);
  await expect(page.getByTestId('selected-count')).toHaveText('3 selected');
  // Clearing the filter does not bring the hidden rows back selected.
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.getByTestId('selected-count')).toHaveText('3 selected');
  await page.getByTestId('filter-type').selectOption('BPF_LOAD');
  await page.getByRole('button', { name: 'Allow — ignore in future' }).click();
  await expect(page.getByTestId('confirm-dialog')).toContainText('Allow 3 new hooks');
  await page.getByTestId('confirm-decision').click();
  await expect(page.getByTestId('decide-summary')).toContainText('Allowed 3 of 3');
  expect([...m.decides[0].ids].sort()).toEqual(['upd-1', 'upd-2', 'upd-3']);
});

test('a live first sighting is announced, not slipped into the list', async ({ page }) => {
  const m = await mockServer(page);
  await page.goto(`${baseURL}/new-hooks`);
  await expect(rows(page)).toHaveCount(6);
  await expect.poll(() => m.sockets.length).toBeGreaterThan(0);
  await page.getByTestId('select-all-shown').check();

  const arrived = entry('late-1', 'EXEC_INJECTION', '/usr/sbin/sshd', { kind: 'library_path', value: '/tmp/libx.so' }, 0, ['host-a']);
  m.pending.push(arrived);
  m.sockets[0].send(
    JSON.stringify({
      id: 'evt-late-1',
      timestamp: new Date().toISOString(),
      host_id: 'host-a',
      hostname: 'web-01',
      event_type: 'EXEC_INJECTION',
      severity: 'CRITICAL',
      policy_result: { action: 'ALERT', reason: 'no allowlist match', disposition: 'first_sighting', candidate_id: 'late-1' },
    })
  );

  await expect(page.getByTestId('new-arrivals')).toContainText('1 new hook arrived since this list loaded');
  await expect(rows(page)).toHaveCount(6);
  await expect(page.getByTestId('selected-count')).toHaveText('6 selected');
  await expect(page.getByTestId('new-hooks-count')).toHaveText('7');
  await page.getByTestId('new-arrivals').getByRole('button', { name: 'Refresh' }).click();
  await expect(rows(page)).toHaveCount(7);
  await expect(page.getByTestId('new-arrivals')).toHaveCount(0);
  await expect(page.getByTestId('selected-count')).toHaveText('6 selected');
});

test('the feed marks first sightings and denied hooks; /pending goes to New hooks', async ({ page }) => {
  const m = await mockServer(page);
  const base = { host_id: 'host-a', hostname: 'web-01', pid: 42, comm: 'x', exe_path: '/usr/bin/x' };
  m.events = [
    { ...base, id: 'e1', timestamp: iso(MIN), event_type: 'BPF_LOAD', severity: 'CRITICAL', policy_result: { action: 'ALERT', reason: 'r', disposition: 'first_sighting', candidate_id: 'upd-1' } },
    { ...base, id: 'e2', timestamp: iso(2 * MIN), event_type: 'PTRACE_INJECT', severity: 'ALERT', policy_result: { action: 'ALERT', reason: 'r', disposition: 'denied', matched_entry_id: 'x' } },
  ];
  await page.goto(`${baseURL}/events`);
  await expect(page.locator('[data-event-id=e1] [data-testid=disposition]')).toHaveText('first sighting');
  await expect(page.locator('[data-event-id=e2] [data-testid=disposition]')).toHaveText('denied');

  await page.goto(`${baseURL}/pending`);
  await expect(page).toHaveURL(/\/new-hooks$/);
  await expect(page.getByRole('heading', { name: 'New hooks' })).toBeVisible();
});
