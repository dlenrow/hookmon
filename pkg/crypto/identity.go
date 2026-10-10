package crypto

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ErrNoHostIdentity means an RPC's connection carries no verified bus
// certificate.
var ErrNoHostIdentity = errors.New("no verified client certificate")

// HostIDFromCert returns the host ID a bus certificate carries: its CN,
// which must be a canonical UUID, in a certificate whose Organization
// includes HostCertOrganization. Both are written by the server when it
// signs, so any other certificate is refused.
func HostIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNoHostIdentity
	}
	if !slices.Contains(cert.Subject.Organization, HostCertOrganization) {
		return "", fmt.Errorf("certificate organization %q does not include %q",
			cert.Subject.Organization, HostCertOrganization)
	}
	id := cert.Subject.CommonName
	u, err := uuid.Parse(id)
	if err != nil || u.String() != id {
		return "", fmt.Errorf("certificate CN %q is not a host ID", id)
	}
	return id, nil
}

// HostIDFromPeer returns the host ID of the bus on the other end of an RPC,
// from the leaf of the client certificate chain the TLS handshake verified.
// Certificates the client sent but the server did not verify are never
// used.
func HostIDFromPeer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", ErrNoHostIdentity
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("%w: connection is not TLS (%s)", ErrNoHostIdentity, p.AuthInfo.AuthType())
	}
	chains := info.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", ErrNoHostIdentity
	}
	return HostIDFromCert(chains[0][0])
}
