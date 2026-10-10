package connectors

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// newHTTPClient returns a client for an HTTP connector. With caFile, the
// sink's certificate must chain to that CA instead of the system roots.
func newHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificate", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// doHTTP sends one request and returns the response body (up to 1 MiB).
// A network error, HTTP 429 or a 5xx is retryable; any other status
// outside 2xx is not.
func doHTTP(ctx context.Context, client *http.Client, method, url string, hdr http.Header, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, retryable(fmt.Errorf("%s %s: %w", method, redactURL(url), err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return data, nil
	}
	err = fmt.Errorf("%s %s: status %d: %s", method, redactURL(url), resp.StatusCode, snippet(data))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return data, retryable(err)
	}
	return data, err
}

// redactURL drops any user info from a URL before it is logged.
func redactURL(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if at := strings.LastIndex(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
			return raw[:i+3] + rest[at+1:]
		}
	}
	return raw
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return s
}
