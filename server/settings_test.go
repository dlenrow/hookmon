package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/server/connectors"
)

// The settings the dashboard shows name tokens and connectors but carry no
// secret: no enrollment or API token, no connector URL or credential.
func TestSettings_NoSecrets(t *testing.T) {
	const (
		enrollSecret = "enroll-secret-0123456789abcdef0123456789abcdef"
		apiToken     = "api-token-secret"
		hookAuth     = "Bearer webhook-secret"
		hookURL      = "https://hooks.example.com/hookmon-secret-path"
	)
	cfg := DefaultConfig()
	cfg.API.Tokens = []string{apiToken}
	cfg.Enrollment.Tokens = []hcrypto.EnrollmentToken{
		{Name: "rollout", Secret: enrollSecret, Expires: time.Now().Add(time.Hour), SingleUse: true},
		{Name: "old", Secret: enrollSecret + "x", Expires: time.Now().Add(-time.Hour)},
	}
	cfg.Connectors = connectors.Config{
		Webhook: &connectors.WebhookConfig{URL: hookURL, Headers: map[string]string{"Authorization": hookAuth}},
		Kafka:   &connectors.KafkaConfig{Brokers: []string{"k1:9092"}, Topic: "t", Delivery: connectors.Delivery{MinSeverity: "info"}},
	}
	d, err := connectors.New(context.Background(), connectors.Config{Webhook: cfg.Connectors.Webhook}, nil, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(context.Background()) })

	s := New(cfg, zap.NewNop())
	s.dispatcher = d
	s.grpcAddr, s.enrollAddr, s.httpAddr = "[::]:9443", "[::]:9444", "[::]:8443"
	st := s.settings()

	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{enrollSecret, apiToken, "webhook-secret", "hookmon-secret-path", "hooks.example.com"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("settings expose %q: %s", secret, data)
		}
	}
	if st.TLS != cfg.UseTLS() || st.GRPCAddr != "[::]:9443" || st.EnrollAddr != "[::]:9444" || !st.Enrollment.Enabled {
		t.Errorf("settings: %+v", st)
	}
	if len(st.Enrollment.Tokens) != 2 || st.Enrollment.Tokens[0].Name != "rollout" || !st.Enrollment.Tokens[0].SingleUse ||
		st.Enrollment.Tokens[0].Expired || !st.Enrollment.Tokens[1].Expired {
		t.Errorf("tokens: %+v", st.Enrollment.Tokens)
	}
	if len(st.Connectors) != 1 || st.Connectors[0].Name != "webhook" || st.Connectors[0].MinSeverity != "ALERT" {
		t.Errorf("connectors: %+v", st.Connectors)
	}
	if m := connectorMinSeverity(cfg.Connectors); m["kafka"] != "INFO" || m["webhook"] != "ALERT" {
		t.Errorf("min severities: %v", m)
	}
}

func TestLoadConfig_AllowedOrigins(t *testing.T) {
	cfg, err := LoadConfig(enrWriteConfig(t, "api:\n  allowed_origins: [\"https://dash.example.com\", \"http://localhost:5173\"]\n"))
	if err != nil || len(cfg.API.AllowedOrigins) != 2 {
		t.Fatalf("valid origins: %v %+v", err, cfg.API)
	}
	for _, bad := range []string{"dash.example.com", "https://dash.example.com/app", "*"} {
		if _, err := LoadConfig(enrWriteConfig(t, "api:\n  allowed_origins: [\""+bad+"\"]\n")); err == nil ||
			!strings.Contains(err.Error(), "allowed_origins") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
