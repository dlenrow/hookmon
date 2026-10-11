package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
)

// ErrServerNotTrusted means the server's TLS certificate did not verify
// against the bus's CA file: the CA file is the wrong one, or the address
// names a host the server's certificate does not cover. Retrying cannot fix
// either, so enrollment, and the first connection after the bus starts,
// stop with this error instead of retrying for ever.
var ErrServerNotTrusted = errors.New("the server's TLS certificate does not verify against the CA file")

// verifyRecorder wraps client transport credentials and records why the
// last handshake failed to verify the server's certificate. gRPC reports a
// failed handshake as a transient Unavailable error, which the bus would
// otherwise retry with backoff for ever.
type verifyRecorder struct {
	credentials.TransportCredentials
	state *verifyState
}

type verifyState struct {
	mu  sync.Mutex
	err error
}

func watchVerify(c credentials.TransportCredentials) *verifyRecorder {
	return &verifyRecorder{TransportCredentials: c, state: &verifyState{}}
}

// ClientHandshake runs the wrapped handshake and records a certificate
// verification failure.
func (r *verifyRecorder) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c, info, err := r.TransportCredentials.ClientHandshake(ctx, authority, conn)
	if err != nil && isVerifyError(err) {
		r.state.mu.Lock()
		r.state.err = err
		r.state.mu.Unlock()
	}
	return c, info, err
}

// Clone keeps the clone recording into the same state.
func (r *verifyRecorder) Clone() credentials.TransportCredentials {
	return &verifyRecorder{TransportCredentials: r.TransportCredentials.Clone(), state: r.state}
}

// take returns the recorded verification failure, if any, and clears it.
func (r *verifyRecorder) take() error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	err := r.state.err
	r.state.err = nil
	return err
}

// isVerifyError reports whether a handshake failed because this side
// could not verify the peer's certificate.
func isVerifyError(err error) bool {
	var cve *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &cve) || errors.As(err, &unknownCA) ||
		errors.As(err, &hostname) || errors.As(err, &invalid)
}

// notTrusted builds the error for a verification failure verr when
// connecting to addr with the CA in caFile.
func notTrusted(addr, caFile string, verr error) error {
	return fmt.Errorf("%w: %s, CA file %s: %v; check that --ca-file (tls.ca_file) is the CA that signed the "+
		"server's certificate, and that the server address is a name in that certificate (or set tls.server_name)",
		ErrServerNotTrusted, addr, caFile, verr)
}

// stopRetrying wraps an error that retrying cannot fix. RetryLoop returns
// its cause at once instead of trying again.
type stopRetrying struct{ err error }

func (s *stopRetrying) Error() string { return s.err.Error() }
func (s *stopRetrying) Unwrap() error { return s.err }
