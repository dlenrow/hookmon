import { useState, useEffect } from 'react';
import { getToken, setToken, clearToken } from '../api/client';

export function Settings() {
  const [apiToken, setApiToken] = useState('');
  const [tokenSaved, setTokenSaved] = useState(false);

  useEffect(() => {
    const stored = getToken();
    if (stored) {
      setApiToken(stored);
    }
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

  return (
    <>
      <div className="page-header">
        <h2>Settings</h2>
        <p>Dashboard configuration and system information</p>
      </div>

      <div className="page-body">
        {/* API Token */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <h3>API Authentication</h3>
          </div>
          <div className="card-body">
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Enter the API token used to authenticate requests to the HookMon server.
              This token is stored in your browser&apos;s local storage.
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

        {/* SIEM Connector Status */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <h3>SIEM Connectors</h3>
          </div>
          <div className="card-body">
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Status of configured SIEM output connectors. Connectors are configured
              in the server configuration file.
            </p>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Connector</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Syslog/CEF</td>
                  <td><span className="badge badge-type">syslog</span></td>
                  <td>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Configure in server YAML
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    RFC 5424 + ArcSight CEF format
                  </td>
                </tr>
                <tr>
                  <td>Splunk HEC</td>
                  <td><span className="badge badge-type">splunk</span></td>
                  <td>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Configure in server YAML
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    HTTP Event Collector endpoint
                  </td>
                </tr>
                <tr>
                  <td>Elasticsearch</td>
                  <td><span className="badge badge-type">elastic</span></td>
                  <td>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Configure in server YAML
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Bulk API indexing
                  </td>
                </tr>
                <tr>
                  <td>Webhook</td>
                  <td><span className="badge badge-type">webhook</span></td>
                  <td>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Configure in server YAML
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Generic JSON webhook output
                  </td>
                </tr>
                <tr>
                  <td>Kafka</td>
                  <td><span className="badge badge-type">kafka</span></td>
                  <td>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Configure in server YAML
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Kafka topic producer
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Agent Enrollment */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-header">
            <h3>Agent Enrollment</h3>
          </div>
          <div className="card-body">
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Use the following command to enroll a new agent. Replace the token and
              hostname with your server&apos;s values.
            </p>
            <pre className="json-display">
{`curl -sSL https://hookmon.internal:9443/enroll | \\
  sudo bash -s -- --token <enrollment-token>`}
            </pre>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '12px' }}>
              Enrollment tokens are generated during the first-boot setup wizard or
              via the hookmon-cli tool.
            </p>
          </div>
        </div>

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
