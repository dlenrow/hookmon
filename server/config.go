package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
)

// DefaultConfigPath is where hookmon-server looks for its config file when
// --config is not given.
const DefaultConfigPath = "/etc/hookmon/server.yaml"

// DefaultDashboardDir is where the server looks for the built dashboard
// unless dashboard_dir says otherwise.
const DefaultDashboardDir = "/usr/share/hookmon/dashboard"

// ErrNoTLS is returned when the server has no TLS certificate and is not
// in insecure mode.
var ErrNoTLS = errors.New("no TLS certificate configured: set tls.cert_file, tls.key_file and tls.ca_file " +
	"(or --tls-cert, --tls-key and --tls-ca), or pass --insecure to run gRPC and REST in plaintext (development only)")

// Config holds the hookmon-server configuration. It is read from a YAML
// file (see deploy/server.example.yaml); command-line flags override it.
type Config struct {
	// GRPCAddr is the mutual-TLS listener for bus event streams.
	GRPCAddr string `yaml:"grpc_addr"`
	// EnrollAddr is the enrollment listener: TLS with server authentication
	// only, serving the Enroll RPC alone. It runs only when enrollment
	// tokens are configured.
	EnrollAddr string `yaml:"enroll_addr"`
	// HTTPAddr is the REST API, WebSocket and dashboard listener. It uses
	// TLS with the server certificate.
	HTTPAddr string `yaml:"http_addr"`

	// DashboardDir holds the built dashboard (index.html and assets, from
	// npm run build). The server serves it on HTTPAddr. Empty turns the
	// dashboard off; a directory without index.html is skipped with a
	// warning.
	DashboardDir string `yaml:"dashboard_dir"`

	TLS        TLSConfig        `yaml:"tls"`
	Database   DatabaseConfig   `yaml:"database"`
	API        APIConfig        `yaml:"api"`
	Enrollment EnrollmentConfig `yaml:"enrollment"`
	Watchdog   WatchdogConfig   `yaml:"watchdog"`

	// Connectors is not read from the config file yet; fix plan step 7d
	// adds a connectors section. Until then, a "connectors" key in the file
	// is an error rather than silently ignored.
	Connectors ConnectorConfigs `yaml:"-"`
}

// TLSConfig holds server TLS settings.
type TLSConfig struct {
	// CertFile and KeyFile are the server's certificate and key, used on the
	// gRPC, enrollment and REST listeners.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// CAFile is the CA certificate that verifies bus client certificates.
	CAFile string `yaml:"ca_file"`
	// CAKeyFile is that CA's private key. Enrollment signs bus certificates
	// with it, so enrollment needs it; nothing else does.
	CAKeyFile string `yaml:"ca_key_file"`
	// Insecure runs gRPC and REST without TLS. Host IDs are then whatever
	// each bus says. Development only. Without it the server refuses to
	// start unless CertFile is set.
	Insecure bool `yaml:"insecure"`
}

// DatabaseConfig holds the PostgreSQL connection settings.
type DatabaseConfig struct {
	URL string `yaml:"url"`
}

// APIConfig holds REST API settings.
type APIConfig struct {
	Tokens []string `yaml:"tokens"`
}

// EnrollmentConfig holds enrollment settings.
type EnrollmentConfig struct {
	// CertValidity is how long a bus certificate lasts. Zero means
	// crypto.DefaultCertValidity (one year).
	CertValidity time.Duration `yaml:"cert_validity"`
	// Tokens are the enrollment secrets. With none, enrollment is off.
	Tokens []hcrypto.EnrollmentToken `yaml:"tokens"`
}

// DefaultConfig returns the configuration used when no file sets a value.
func DefaultConfig() Config {
	return Config{
		GRPCAddr:     ":9443",
		EnrollAddr:   ":9444",
		HTTPAddr:     ":8443",
		DashboardDir: DefaultDashboardDir,
		Database: DatabaseConfig{
			URL: "postgres://hookmon:hookmon@localhost:5432/hookmon?sslmode=disable",
		},
		Enrollment: EnrollmentConfig{CertValidity: hcrypto.DefaultCertValidity},
		Watchdog:   DefaultWatchdogConfig(),
	}
}

// LoadConfig reads a YAML config file over DefaultConfig. Unknown keys are
// an error, so a misspelled security setting is never silently ignored.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// UseTLS reports whether the gRPC and REST listeners use TLS.
func (c *Config) UseTLS() bool {
	return !c.TLS.Insecure && c.TLS.CertFile != ""
}

// CheckTLS returns ErrNoTLS unless the server has a certificate or is in
// insecure mode. It is separate from Validate because a config file may
// leave TLS to the command-line flags; the server runs it once both are
// applied.
func (c *Config) CheckTLS() error {
	if c.TLS.Insecure || c.TLS.CertFile != "" {
		return nil
	}
	return ErrNoTLS
}

// Validate checks the settings that depend on each other. It does not read
// any files.
func (c *Config) Validate() error {
	if _, err := hcrypto.NewTokenSet(c.Enrollment.Tokens); err != nil {
		return err
	}
	if c.TLS.CertFile != "" && c.TLS.KeyFile == "" {
		return errors.New("tls.key_file is required with tls.cert_file")
	}
	if c.UseTLS() && c.TLS.CAFile == "" {
		return errors.New("tls.ca_file is required with tls.cert_file: it verifies bus certificates")
	}
	if len(c.Enrollment.Tokens) > 0 {
		if !c.UseTLS() {
			return errors.New("enrollment needs TLS: set tls.cert_file, key_file, ca_file and ca_key_file")
		}
		if c.TLS.CAKeyFile == "" {
			return errors.New("enrollment needs tls.ca_key_file to sign bus certificates")
		}
		if c.EnrollAddr == "" {
			return errors.New("enrollment needs enroll_addr")
		}
	}
	if c.Enrollment.CertValidity < 0 {
		return errors.New("enrollment.cert_validity must not be negative")
	}
	if c.Watchdog.CheckInterval <= 0 || c.Watchdog.HeartbeatTimeout <= 0 {
		return errors.New("watchdog.check_interval and watchdog.heartbeat_timeout must be positive")
	}
	return nil
}
