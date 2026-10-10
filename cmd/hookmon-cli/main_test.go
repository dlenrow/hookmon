package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The API is TLS-only since step 7b: the client must trust the CA given
// with --ca-file, and must not fall back to accepting any certificate.
func TestNewHTTPClientTrustsCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	withCA, err := newHTTPClient(caFile)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := withCA.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with --ca-file: %v", err)
	}
	resp.Body.Close()

	plain, err := newHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := plain.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("GET without the CA succeeded; the server certificate must not be trusted")
	}

	if _, err := newHTTPClient(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Error("missing CA file accepted")
	}
}
