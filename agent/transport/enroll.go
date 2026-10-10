package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dlenrow/hookmon/agent/config"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/version"
)

// Identity files in the bus state directory, each written with mode 0600.
const (
	KeyFileName  = "bus.key" // the bus's private key
	CertFileName = "bus.crt" // its client certificate; CN is the host ID
	CAFileName   = "ca.crt"  // the CA that signed the server and the bus
)

// DefaultEnrollPort is the server's enrollment port. The enrollment address
// defaults to the server_addr host on this port.
const DefaultEnrollPort = "9444"

// enrollCallTimeout bounds one Enroll RPC.
const enrollCallTimeout = 30 * time.Second

// ErrNoIdentity is returned when the bus has no client certificate, no
// enrollment token and no --insecure: it will not connect in plaintext.
var ErrNoIdentity = errors.New("no client certificate and no enrollment token: refusing to connect to the server without TLS; " +
	"enroll with --enroll-token and --ca-file, set tls.cert_file, or pass --insecure to connect without TLS (development only)")

// EnsureIdentity makes sure the bus has a client certificate before the
// transport connects, and sets cfg.TLS and cfg.HostID to match. In order:
//
//  1. TLS.Insecure (--insecure): nothing to do; the bus connects without
//     TLS.
//  2. TLS.CertFile set: that certificate is used as configured.
//  3. bus.crt and bus.key in StateDir: the identity from an earlier
//     enrollment is used. EnrollToken is ignored.
//  4. EnrollToken set: the bus generates a key, enrolls at the enrollment
//     address over TLS that verifies the server against TLS.CAFile, and
//     stores the key, certificate and CA in StateDir. Transient failures
//     (server unreachable) are retried with backoff until ctx ends; a
//     rejected token or request is returned at once.
//  5. Otherwise the bus has no certificate. It refuses to connect without
//     TLS and returns ErrNoIdentity.
func EnsureIdentity(ctx context.Context, cfg *config.AgentConfig, logger *zap.Logger, retry RetryConfig) error {
	if cfg.TLS.Insecure {
		return nil
	}
	if cfg.TLS.CertFile != "" {
		if cfg.EnrollToken != "" {
			logger.Info("tls.cert_file is configured; not enrolling", zap.String("cert", cfg.TLS.CertFile))
		}
		if id, err := hostIDFromCertFile(cfg.TLS.CertFile); err == nil {
			cfg.HostID = id
		}
		return nil
	}
	if cfg.StateDir == "" {
		if cfg.EnrollToken != "" {
			return errors.New("enrollment needs a state directory (state_dir)")
		}
		return ErrNoIdentity
	}

	keyPath := filepath.Join(cfg.StateDir, KeyFileName)
	certPath := filepath.Join(cfg.StateDir, CertFileName)
	caPath := filepath.Join(cfg.StateDir, CAFileName)

	if fileExists(certPath) && fileExists(keyPath) {
		if cfg.EnrollToken != "" {
			logger.Info("already enrolled; ignoring the enrollment token", zap.String("cert", certPath))
		}
		return useIdentity(cfg, keyPath, certPath, caPath, logger)
	}

	if cfg.EnrollToken == "" {
		return ErrNoIdentity
	}
	if err := enroll(ctx, cfg, keyPath, certPath, caPath, logger, retry); err != nil {
		return err
	}
	return useIdentity(cfg, keyPath, certPath, caPath, logger)
}

// useIdentity points cfg at the identity files in the state directory.
func useIdentity(cfg *config.AgentConfig, keyPath, certPath, caPath string, logger *zap.Logger) error {
	id, err := hostIDFromCertFile(certPath)
	if err != nil {
		return fmt.Errorf("enrolled certificate %s: %w", certPath, err)
	}
	cfg.HostID = id
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath
	if cfg.TLS.CAFile == "" {
		cfg.TLS.CAFile = caPath
	}
	logger.Info("using enrolled identity", zap.String("host_id", id), zap.String("cert", certPath))
	return nil
}

// enroll runs the enrollment exchange and writes the identity files. The
// key is written before the request, so no certificate is issued for a key
// the bus did not keep; the certificate is written last, so bus.crt exists
// only for a complete identity.
func enroll(ctx context.Context, cfg *config.AgentConfig, keyPath, certPath, caPath string, logger *zap.Logger, retry RetryConfig) error {
	if cfg.TLS.CAFile == "" {
		return errors.New("enrollment needs the CA certificate that signed the server's certificate (--ca-file)")
	}
	caPEM, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	creds, err := hcrypto.EnrollClientTLS(caPEM, cfg.TLS.ServerName)
	if err != nil {
		return fmt.Errorf("CA certificate %s: %w", cfg.TLS.CAFile, err)
	}
	addr, err := enrollAddr(cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := hcrypto.GenerateAgentKeypair(hostname)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, keyPEM); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial enrollment server: %w", err)
	}
	defer conn.Close()
	client := hookmonv1.NewAgentServiceClient(conn)
	req := &hookmonv1.EnrollRequest{
		EnrollmentToken: cfg.EnrollToken,
		Hostname:        hostname,
		Csr:             csrPEM,
		OsInfo:          osInfo(),
		AgentVersion:    version.Version,
	}

	logger.Info("enrolling with server", zap.String("addr", addr), zap.String("hostname", hostname))
	var resp *hookmonv1.EnrollResponse
	err = retryEnroll(ctx, retry, logger, func(ctx context.Context) error {
		callCtx, cancel := context.WithTimeout(ctx, enrollCallTimeout)
		defer cancel()
		var err error
		resp, err = client.Enroll(callCtx, req)
		return err
	})
	if err != nil {
		return fmt.Errorf("enroll with %s: %w", addr, err)
	}

	certPEM, hostID, err := checkEnrollment(resp, keyPEM, caPEM)
	if err != nil {
		return fmt.Errorf("enrollment response: %w", err)
	}
	if err := writeFileAtomic(caPath, caPEM); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := writeFileAtomic(certPath, certPEM); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	logger.Info("enrolled", zap.String("host_id", hostID), zap.String("state_dir", cfg.StateDir))
	return nil
}

// retryEnroll calls fn until it succeeds, fails permanently, or ctx ends,
// with exponential backoff between attempts.
func retryEnroll(ctx context.Context, cfg RetryConfig, logger *zap.Logger, fn func(context.Context) error) error {
	delay := cfg.InitialDelay
	if delay <= 0 {
		delay = time.Second
	}
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if permanentEnrollError(err) || (cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts) {
			return err
		}
		logger.Warn("enrollment attempt failed, retrying",
			zap.Int("attempt", attempt), zap.Duration("next_retry", delay), zap.Error(err))
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(delay):
		}
		if cfg.Multiplier > 1 {
			delay = time.Duration(math.Min(float64(delay)*cfg.Multiplier, float64(cfg.MaxDelay)))
		}
	}
}

// permanentEnrollError reports whether retrying the same request cannot
// help: the server rejected the token or the request.
func permanentEnrollError(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated,
		codes.FailedPrecondition, codes.Unimplemented, codes.NotFound, codes.AlreadyExists:
		return true
	}
	return false
}

// checkEnrollment verifies the server's response before the bus stores it:
// the certificate must be for the bus's own key, chain to the CA the bus
// was given (not the one in the response), be a client certificate, and
// carry the host ID the response names.
func checkEnrollment(resp *hookmonv1.EnrollResponse, keyPEM, caPEM []byte) (certPEM []byte, hostID string, err error) {
	block, _ := pem.Decode(resp.GetSignedCert())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", errors.New("signed certificate is not a PEM certificate")
	}
	certPEM = pem.EncodeToMemory(block)
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, "", fmt.Errorf("signed certificate does not match the bus key: %w", err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse signed certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("parse CA certificate")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, "", fmt.Errorf("signed certificate does not verify against the CA: %w", err)
	}
	hostID, err = hcrypto.HostIDFromCert(cert)
	if err != nil {
		return nil, "", err
	}
	if hostID != resp.GetHostId() {
		return nil, "", fmt.Errorf("certificate is for host %s, response names %s", hostID, resp.GetHostId())
	}
	return certPEM, hostID, nil
}

// enrollAddr returns the configured enrollment address, or the server_addr
// host on DefaultEnrollPort.
func enrollAddr(cfg *config.AgentConfig) (string, error) {
	if cfg.EnrollAddr != "" {
		return cfg.EnrollAddr, nil
	}
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return "", fmt.Errorf("derive the enrollment address from server_addr %q: %w; set enroll_addr", cfg.ServerAddr, err)
	}
	return net.JoinHostPort(host, DefaultEnrollPort), nil
}

func hostIDFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return hcrypto.HostIDFromCert(cert)
}

// writeFileAtomic writes data to path with mode 0600, through a temporary
// file in the same directory and a rename.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// osInfo describes the host for the inventory, from /etc/os-release.
func osInfo() string {
	info := runtime.GOOS + "/" + runtime.GOARCH
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return info
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`) + " (" + info + ")"
		}
	}
	return info
}
