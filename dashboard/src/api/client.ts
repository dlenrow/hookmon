import type {
  HookEvent,
  AllowlistEntry,
  EntryStatus,
  Host,
  EventQueryParams,
  LearningState,
  Scope,
  BulkDecision,
  BulkScope,
  DecideResponse,
  ServerSettings,
} from './types';

const API_BASE = '/api/v1';
const TOKEN_KEY = 'hookmon_api_token';

/**
 * Get the stored API token from localStorage.
 */
export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) || '';
}

/**
 * Set the API token in localStorage.
 */
export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

/**
 * Clear the stored API token.
 */
export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/**
 * Build headers with Bearer token authentication.
 */
function authHeaders(extra?: Record<string, string>): HeadersInit {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...extra,
  };
  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Generic fetch wrapper with error handling.
 */
async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: authHeaders(init?.headers as Record<string, string>),
  });

  if (!response.ok) {
    let message = `API error: ${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.error) {
        message = body.error;
      }
    } catch {
      // Ignore parse errors
    }
    throw new Error(message);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

/**
 * Build query string from EventQueryParams, omitting undefined values.
 */
function buildQueryString(params: EventQueryParams): string {
  const searchParams = new URLSearchParams();
  if (params.limit !== undefined) searchParams.set('limit', String(params.limit));
  if (params.offset !== undefined) searchParams.set('offset', String(params.offset));
  if (params.host_id) searchParams.set('host_id', params.host_id);
  if (params.event_type) searchParams.set('event_type', params.event_type);
  if (params.severity) searchParams.set('severity', params.severity);
  if (params.since) searchParams.set('since', params.since);
  if (params.until) searchParams.set('until', params.until);
  const qs = searchParams.toString();
  return qs ? `?${qs}` : '';
}

// --- Events ---

/**
 * Query events with optional filters.
 */
export async function getEvents(params: EventQueryParams = {}): Promise<HookEvent[]> {
  return apiFetch<HookEvent[]>(`/events${buildQueryString(params)}`);
}

/**
 * Get a single event by ID.
 */
export async function getEvent(id: string): Promise<HookEvent> {
  return apiFetch<HookEvent>(`/events/${encodeURIComponent(id)}`);
}

/**
 * Create an ALLOW entry that matches exactly the events with this event's
 * learning-mode key (event type, binary hash, subject such as the BPF tag,
 * container context), for the fleet or for the event's host.
 */
export async function allowlistEvent(
  id: string,
  scope: 'fleet' | 'host',
  description?: string
): Promise<AllowlistEntry> {
  return apiFetch<AllowlistEntry>(`/events/${encodeURIComponent(id)}/allowlist`, {
    method: 'POST',
    body: JSON.stringify(description ? { scope, description } : { scope }),
  });
}

// --- Hosts ---

/**
 * List all monitored hosts.
 */
export async function getHosts(): Promise<Host[]> {
  return apiFetch<Host[]>('/hosts');
}

/**
 * Get a single host by ID.
 */
export async function getHost(id: string): Promise<Host> {
  return apiFetch<Host>(`/hosts/${encodeURIComponent(id)}`);
}

// --- Policies ---

/**
 * List allowlist entries: by default those in force (APPROVED and
 * REJECTED), or those with the given statuses.
 */
export async function getPolicies(...statuses: EntryStatus[]): Promise<AllowlistEntry[]> {
  const qs = statuses.length ? `?status=${statuses.join(',')}` : '';
  return apiFetch<AllowlistEntry[]>(`/policies${qs}`);
}

/**
 * Create a new allowlist entry.
 */
export async function createPolicy(entry: Partial<AllowlistEntry>): Promise<AllowlistEntry> {
  return apiFetch<AllowlistEntry>('/policies', {
    method: 'POST',
    body: JSON.stringify(entry),
  });
}

/**
 * Replace an entry's criteria, action, expiry, description and enabled flag.
 */
export async function updatePolicy(id: string, entry: Partial<AllowlistEntry>): Promise<AllowlistEntry> {
  return apiFetch<AllowlistEntry>(`/policies/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(entry),
  });
}

/**
 * Change some of an entry's editable fields, such as { enabled: false }.
 */
export async function patchPolicy(id: string, patch: Partial<AllowlistEntry>): Promise<AllowlistEntry> {
  return apiFetch<AllowlistEntry>(`/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

/**
 * Delete an allowlist entry by ID.
 */
export async function deletePolicy(id: string): Promise<void> {
  return apiFetch<void>(`/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

/**
 * Approve (ALLOW) or reject (keep alerting) a PENDING learning-mode entry,
 * for the fleet or for one host.
 */
export async function decidePolicy(
  id: string,
  decision: 'approve' | 'reject',
  scope: Scope
): Promise<AllowlistEntry> {
  return apiFetch<AllowlistEntry>(`/policies/${encodeURIComponent(id)}/${decision}`, {
    method: 'POST',
    body: JSON.stringify(scope),
  });
}

/**
 * Decide several PENDING entries (new hooks) at once: approve (ALLOW, never
 * alerts again) or reject (keeps alerting every time), for the fleet or for
 * the hosts each was seen on. The server decides them in one transaction
 * and reports each ID: one that is no longer PENDING fails alone.
 */
export async function decidePolicies(
  ids: string[],
  decision: BulkDecision,
  scope: BulkScope
): Promise<DecideResponse> {
  return apiFetch<DecideResponse>('/policies/decide', {
    method: 'POST',
    body: JSON.stringify({ ids, decision, scope }),
  });
}

// --- Learning mode (a quiet period: first sightings are listed but not sent to alert connectors) ---

export async function getLearning(): Promise<LearningState> {
  return apiFetch<LearningState>('/learning');
}

// --- Settings ---

export async function getSettings(): Promise<ServerSettings> {
  return apiFetch<ServerSettings>('/settings');
}

// --- WebSocket ---

/** The subprotocol of the live event feed. */
export const WS_PROTOCOL = 'hookmon.v1';
/**
 * A browser cannot set an Authorization header on a WebSocket, and a token
 * in the URL ends up in logs, so the token travels as a second offered
 * subprotocol: this prefix plus the token as unpadded base64url.
 */
const WS_TOKEN_PREFIX = 'hookmon.bearer.';

function base64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** live: connected; reconnecting: waiting to retry; no-token: no API token set. */
export type WebSocketState = 'live' | 'reconnecting' | 'no-token';

export type WebSocketEventHandler = (event: HookEvent) => void;
export type WebSocketStateHandler = (state: WebSocketState) => void;

interface WebSocketConnection {
  close: () => void;
}

/** Close code the server uses for a client that fell behind the feed. */
const CLOSE_TRY_AGAIN_LATER = 1013;

/**
 * Connect to the real-time event WebSocket stream. It reconnects with
 * backoff; each time the state becomes 'live' the feed restarts, so callers
 * reload recent events over REST to cover any gap.
 * Returns an object with a close() method to disconnect.
 */
export function connectWebSocket(
  onEvent: WebSocketEventHandler,
  onState?: WebSocketStateHandler
): WebSocketConnection {
  const token = getToken();
  if (!token) {
    onState?.('no-token');
    return { close() {} };
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}${API_BASE}/ws/events`;
  const protocols = [WS_PROTOCOL, WS_TOKEN_PREFIX + base64url(token)];

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;
  let delay = 1000;

  function connect() {
    if (closed) return;

    ws = new WebSocket(wsUrl, protocols);

    ws.onopen = () => {
      delay = 1000;
      onState?.('live');
    };

    ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data) as HookEvent;
        onEvent(event);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = (ev) => {
      if (closed) return;
      onState?.('reconnecting');
      // A client dropped for falling behind may retry at once; otherwise
      // back off up to 30 s (a wrong token or origin keeps failing).
      const wait = ev.code === CLOSE_TRY_AGAIN_LATER ? 1000 : delay;
      delay = Math.min(delay * 2, 30000);
      reconnectTimer = setTimeout(connect, wait);
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  connect();

  return {
    close() {
      closed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      ws?.close();
    },
  };
}
