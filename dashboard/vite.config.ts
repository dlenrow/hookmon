import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

// `npm run dev` serves the dashboard on http://localhost:5173 (3000 is
// Grafana's) and proxies /api, the WebSocket feed included, to a
// hookmon-server over HTTPS.
//
//   HOOKMON_API_URL  the server's REST address (default https://localhost:8443)
//   HOOKMON_CA_FILE  the CA that signed the server certificate; the proxy
//                    then verifies the server. Without it the proxy accepts
//                    any certificate (development only).
//
// The server accepts WebSocket handshakes only from its own origin, and the
// proxy passes the browser's Origin through unchanged, so for the live feed
// add the dev origin to the server config:
//
//   api:
//     allowed_origins: ["http://localhost:5173"]
const apiURL = new URL(process.env.HOOKMON_API_URL || 'https://localhost:8443');
const caFile = process.env.HOOKMON_CA_FILE;
const ca = caFile ? fs.readFileSync(caFile) : undefined;

export default defineConfig(({ command }) => {
  if (command === 'serve' && apiURL.protocol === 'https:' && !ca) {
    console.warn('vite proxy: HOOKMON_CA_FILE is not set, so the proxy does not verify the server certificate');
  }
  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          // http-proxy hands ca from the target object to the TLS client,
          // for REST requests and WebSocket upgrades alike.
          target: {
            protocol: apiURL.protocol,
            host: apiURL.hostname,
            port: Number(apiURL.port) || (apiURL.protocol === 'https:' ? 443 : 80),
            ca,
          },
          changeOrigin: true,
          secure: !!ca,
          ws: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
    },
  };
});
