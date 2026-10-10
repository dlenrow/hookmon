package crypto_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/test/enrpki"
)

func enrPeerCtx(info credentials.AuthInfo) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		AuthInfo: info,
	})
}

func enrLeaf(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestHostIDFromPeer(t *testing.T) {
	p := enrpki.New(t)
	hostID := uuid.New().String()
	good := enrLeaf(t, p.ClientCert(t, hostID, hcrypto.HostCertOrganization))
	verified := func(c *x509.Certificate) credentials.TLSInfo {
		return credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{c},
			VerifiedChains:   [][]*x509.Certificate{{c}},
		}}
	}

	got, err := hcrypto.HostIDFromPeer(enrPeerCtx(verified(good)))
	if err != nil || got != hostID {
		t.Fatalf("verified bus certificate: got (%q, %v), want %q", got, err, hostID)
	}

	cases := map[string]context.Context{
		"no peer":      context.Background(),
		"no auth info": enrPeerCtx(nil),
		"not TLS":      enrPeerCtx(enrAuthInfo("insecure")),
		// The client sent a certificate but the handshake did not verify it.
		"unverified certificate": enrPeerCtx(credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{good},
		}}),
		"no certificate": enrPeerCtx(credentials.TLSInfo{}),
		"CN not a host ID": enrPeerCtx(verified(enrLeaf(t,
			p.ClientCert(t, "hookmon-server", hcrypto.HostCertOrganization)))),
		"CN not canonical": enrPeerCtx(verified(enrLeaf(t,
			p.ClientCert(t, "{"+hostID+"}", hcrypto.HostCertOrganization)))),
		"wrong organization": enrPeerCtx(verified(enrLeaf(t,
			p.ClientCert(t, uuid.New().String(), "someone-else")))),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := hcrypto.HostIDFromPeer(ctx); err == nil {
				t.Fatalf("got host ID %q, want an error", got)
			}
		})
	}

	if _, err := hcrypto.HostIDFromPeer(context.Background()); !errors.Is(err, hcrypto.ErrNoHostIdentity) {
		t.Errorf("no peer: got %v, want ErrNoHostIdentity", err)
	}
}

// enrAuthInfo is a non-TLS AuthInfo.
type enrAuthInfo string

func (a enrAuthInfo) AuthType() string { return string(a) }
