import type {
  HookEvent,
  AllowlistEntry,
  Host,
  EventQueryParams,
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
 * List all allowlist/policy entries.
 */
export async function getPolicies(): Promise<AllowlistEntry[]> {
  return apiFetch<AllowlistEntry[]>('/policies');
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
 * Delete an allowlist entry by ID.
 */
export async function deletePolicy(id: string): Promise<void> {
  return apiFetch<void>(`/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// --- WebSocket ---

export type WebSocketEventHandler = (event: HookEvent) => void;
export type WebSocketStatusHandler = (connected: boolean) => void;

interface WebSocketConnection {
  close: () => void;
}

/**
 * Connect to the real-time event WebSocket stream.
 * Returns an object with a close() method to disconnect.
 */
export function connectWebSocket(
  onEvent: WebSocketEventHandler,
  onStatus?: WebSocketStatusHandler
): WebSocketConnection {
  const token = getToken();
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}${API_BASE}/ws/events?token=${encodeURIComponent(token)}`;

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  function connect() {
    if (closed) return;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      onStatus?.(true);
    };

    ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data) as HookEvent;
        onEvent(event);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      onStatus?.(false);
      if (!closed) {
        // Reconnect after 3 seconds
        reconnectTimer = setTimeout(connect, 3000);
      }
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
