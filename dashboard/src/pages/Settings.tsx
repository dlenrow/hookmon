import { useState, useEffect } from 'react';
import type { ServerSettings } from '../api/types';
import { getToken, setToken, clearToken, getSettings } from '../api/client';
import { addrPort, formatTimestamp } from '../utils';

/** The bus's default state directory, where enrollment stores its key and certificates. */
const STATE_DIR = '/var/lib/hookmon';

/**
 * The command that enrolls a sensor bus with this server, built from the
 * server's bound ports and the host name the dashboard was loaded from.
 */
function enrollCommand(s: ServerSettings, host: string): string {
  const lines = [
    'sudo hookmon-bus --enroll-token-file /etc/hookmon/enroll-token \\',
    `  --server-addr ${host}:${addrPort(s.grpc_addr)} \\`,
    `  --enroll-addr ${host}:${addrPort(s.enroll_addr)} \\`,
    '  --ca-file /path/to/ca.crt \\',
    `  --state-dir ${STATE_DIR}`,
  ];
  return lines.join('\n');
}

export function Settings() {
  const [apiToken, setApiToken] = useState('');
  const [tokenSaved, setTokenSaved] = useState(false);
  const [settings, setSettings] = useState<ServerSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = getToken();
    if (stored) {
      setApiToken(stored);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    getSettings()
      .then((s) => {
        if (!cancelled) setSettings(s);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load server settings');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function handleSaveToken() {
    if (apiToken.trim()) {
      setToken(apiToken.trim());
    } else {
      clearToken();
    }
    setTokenSaved(true);
    setTimeout(() => setTokenSaved(false), 3000);
  }

  const host = window.location.hostname;

  return (
    <>
      <div className="page-header">
        <h2>Settings</h2>
        <p>Dashboard configuration, bus enrollment and server status</p>
      </div>

      <div className="page-body">
        {/* API Token */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <h3>API Authentication</h3>
          </div>
          <div className="card-body">
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Enter one of the server&apos;s API tokens (<span className="mono">api.tokens</span> in
              server.yaml). It is stored in your browser&apos;s local storage and sent as a bearer token, and to
              the live event feed as a WebSocket subprotocol, never in a URL.
            </p>
            <div className="form-group">
              <label className="form-label">API Token</label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="password"
                  className="form-input"
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  placeholder="Enter your API token"
                  style={{ flex: 1 }}
                />
                <button className="btn btn-primary" onClick={handleSaveToken}>
                  Save
                </button>
              </div>
              {tokenSaved && (
                <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--success)' }}>
                  Token saved successfully. Reload the page to apply.
                </div>
              )}
            </div>
          </div>
        </div>

        {error && <div className="error-banner">{error}</div>}

        {settings && (
          <>
            {/* Bus Enrollment */}
            <div className="card" style={{ marginBottom: '24px' }}>
              <div className="card-header">
                <h3>Sensor Bus Enrollment</h3>
              </div>
              <div className="card-body">
                {settings.enrollment.enabled ? (
                  <>
                    <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                      Copy the CA certificate (<span className="mono">ca.crt</span>, not{' '}
                      <span className="mono">ca.key</span>) to the host, then start the bus once with an
                      enrollment token. It enrolls on port {addrPort(settings.enroll_addr)}, stores its key and
                      certificates in <span className="mono">{STATE_DIR}</span> (mode 0600), and connects on port{' '}
                      {addrPort(settings.grpc_addr)} with mutual TLS. Later starts need no token. Use the host
                      name your server certificate names if it is not <span className="mono">{host}</span>.
                    </p>
                    <pre className="json-display" data-testid="enroll-command">
                      {enrollCommand(settings, host)}
                    </pre>
                    <table className="data-table" style={{ marginTop: '16px' }}>
                      <thead>
                        <tr>
                          <th>Enrollment token</th>
                          <th>Expires</th>
                          <th>Use</th>
                        </tr>
                      </thead>
                      <tbody>
                        {settings.enrollment.tokens.map((t) => (
                          <tr key={t.name}>
                            <td className="mono">{t.name}</td>
                            <td style={{ color: t.expired ? 'var(--danger)' : undefined }}>
                              {formatTimestamp(t.expires)}
                              {t.expired ? ' (expired)' : ''}
                            </td>
                            <td>{t.single_use ? 'single use' : 'reusable'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '12px' }}>
                      Token secrets are set in <span className="mono">enrollment.tokens</span> in server.yaml and
                      are never shown here.
                    </p>
                  </>
                ) : (
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }} data-testid="enroll-off">
                    Enrollment is off: the server has no enrollment tokens. Add them under{' '}
                    <span className="mono">enrollment.tokens</span> in server.yaml (a secret from{' '}
                    <span className="mono">openssl rand -hex 32</span>, a name and an expiry) and restart the
                    server.
                  </p>
                )}
              </div>
            </div>

            {/* Server */}
            <div className="card" style={{ marginBottom: '24px' }}>
              <div className="card-header">
                <h3>Server</h3>
              </div>
              <div className="card-body">
                <div className="detail-grid" style={{ gridTemplateColumns: '200px 1fr' }} data-testid="server-ports">
                  <span className="detail-label">Version</span>
                  <span className="detail-value mono">{settings.version}</span>

                  <span className="detail-label">TLS</span>
                  <span className="detail-value">{settings.tls ? 'on' : 'off (--insecure, development only)'}</span>

                  <span className="detail-label">Bus events (gRPC, mTLS)</span>
                  <span className="detail-value mono">{settings.grpc_addr}</span>

                  <span className="detail-label">Enrollment</span>
                  <span className="detail-value mono">{settings.enroll_addr || 'off'}</span>

                  <span className="detail-label">REST, WebSocket, dashboard</span>
                  <span className="detail-value mono">{settings.http_addr}</span>

                  <span className="detail-label">Live feed clients</span>
                  <span className="detail-value">
                    {settings.websocket.subscribers} connected; {settings.websocket.published} events sent;{' '}
                    {settings.websocket.lagged} dropped for falling {settings.websocket.buffer} events behind
                  </span>

                  <span className="detail-label">Extra allowed origins</span>
                  <span className="detail-value mono">
                    {settings.websocket.allowed_origins.length ? settings.websocket.allowed_origins.join(', ') : 'none'}
                  </span>
                </div>
              </div>
            </div>

            {/* SIEM Connector Status */}
            <div className="card" style={{ marginBottom: '24px' }}>
              <div className="card-header">
                <h3>SIEM Connectors</h3>
              </div>
              <div className="card-body">
                {settings.connectors.length === 0 ? (
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }} data-testid="connectors-none">
                    No connectors configured. Add Syslog/CEF, Splunk HEC, Elasticsearch, webhook or Kafka under{' '}
                    <span className="mono">connectors</span> in server.yaml and restart the server.
                  </p>
                ) : (
                  <>
                    <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                      Counts since the server started. Targets and credentials stay in server.yaml.
                    </p>
                    <table className="data-table" data-testid="connectors">
                      <thead>
                        <tr>
                          <th>Connector</th>
                          <th>Receives</th>
                          <th>Sent</th>
                          <th>Failed</th>
                          <th>Dropped (queue full)</th>
                          <th>Queued</th>
                        </tr>
                      </thead>
                      <tbody>
                        {settings.connectors.map((c) => (
                          <tr key={c.name}>
                            <td>
                              <span className="badge badge-type">{c.name}</span>
                            </td>
                            <td style={{ fontSize: '12px' }}>
                              {c.min_severity === 'ALERT' || c.min_severity === 'CRITICAL'
                                ? `alerts at ${c.min_severity} or above`
                                : `every event at ${c.min_severity} or above`}
                            </td>
                            <td className="mono">{c.sent}</td>
                            <td className="mono" style={{ color: c.failed ? 'var(--danger)' : undefined }}>{c.failed}</td>
                            <td className="mono" style={{ color: c.dropped ? 'var(--danger)' : undefined }}>{c.dropped}</td>
                            <td className="mono">{c.queued}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            </div>
          </>
        )}

        {/* About */}
        <div className="card">
          <div className="card-header">
            <h3>About HookMon</h3>
          </div>
          <div className="card-body">
            <div className="detail-grid" style={{ gridTemplateColumns: '120px 1fr' }}>
              <span className="detail-label">Product</span>
              <span className="detail-value">HookMon Security Appliance</span>

              <span className="detail-label">License</span>
              <span className="detail-value">Apache 2.0</span>

              <span className="detail-label">Repository</span>
              <span className="detail-value">
                <a
                  href="https://github.com/dlenrow/hookmon"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: 'var(--text-accent)' }}
                >
                  github.com/dlenrow/hookmon
                </a>
              </span>

              <span className="detail-label">Purpose</span>
              <span className="detail-value" style={{ color: 'var(--text-secondary)' }}>
                Detect, log, and enforce policy on eBPF program loading and LD_PRELOAD
                library injection across enterprise Linux infrastructure.
              </span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
