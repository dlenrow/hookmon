package ingestion

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
)

// maxEnrollField bounds the hostname, OS and version strings a bus sends.
const maxEnrollField = 255

// EnrollStore is the persistence the Enroller needs.
type EnrollStore interface {
	// EnrollHost adds a newly enrolled host to the inventory. When
	// consumeFingerprint is not empty the token is single-use: EnrollHost
	// records it as used in the same transaction, and returns
	// crypto.ErrTokenUsed, adding nothing, if it was used before.
	EnrollHost(ctx context.Context, host *event.Host, tokenName, consumeFingerprint string) error
}

// EnrollerConfig holds the parameters needed to construct an Enroller.
type EnrollerConfig struct {
	Store  EnrollStore
	Tokens *hcrypto.TokenSet
	CA     *hcrypto.CA
	// CertValidity is how long issued certificates last. Zero means
	// crypto.DefaultCertValidity.
	CertValidity time.Duration
	Logger       *zap.Logger
	// Now is the clock for token expiry. Nil means time.Now.
	Now func() time.Time
}

// Enroller serves the Enroll RPC of hookmonv1.AgentService on the
// enrollment listener, which authenticates the server but not the client.
// It checks the enrollment token, assigns a host ID, signs the bus's CSR
// with that ID as the CN, and adds the host to the inventory. StreamEvents
// is not served there.
type Enroller struct {
	hookmonv1.UnimplementedAgentServiceServer

	store    EnrollStore
	tokens   *hcrypto.TokenSet
	ca       *hcrypto.CA
	validity time.Duration
	logger   *zap.Logger
	now      func() time.Time
}

// NewEnroller creates an Enroller.
func NewEnroller(cfg EnrollerConfig) *Enroller {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Enroller{
		store:    cfg.Store,
		tokens:   cfg.Tokens,
		ca:       cfg.CA,
		validity: cfg.CertValidity,
		logger:   cfg.Logger,
		now:      cfg.Now,
	}
}

// Enroll validates the token and request, signs the CSR for a new host ID
// and registers the host. It returns the signed certificate and the CA
// certificate.
func (e *Enroller) Enroll(ctx context.Context, req *hookmonv1.EnrollRequest) (*hookmonv1.EnrollResponse, error) {
	peerIP := peerIP(ctx)
	if e.ca == nil || e.tokens.Len() == 0 {
		return nil, status.Error(codes.FailedPrecondition, "enrollment is not configured on this server")
	}
	if req.EnrollmentToken == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment token is required")
	}

	match, err := e.tokens.Validate(req.EnrollmentToken, e.now())
	if err != nil {
		e.logger.Warn("enrollment rejected",
			zap.String("hostname", req.Hostname),
			zap.String("peer", peerIP),
			zap.Error(err),
		)
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}

	if req.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname is required")
	}
	if len(req.Hostname) > maxEnrollField || len(req.OsInfo) > maxEnrollField || len(req.AgentVersion) > maxEnrollField {
		return nil, status.Errorf(codes.InvalidArgument, "hostname, os_info and agent_version must be at most %d bytes", maxEnrollField)
	}
	if len(req.Csr) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CSR is required")
	}

	// The server, not the bus, chooses the host ID. It becomes the
	// certificate's CN, and from then on the certificate is the identity.
	hostID := uuid.New().String()
	certPEM, err := e.ca.SignCSR(req.Csr, hostID, e.validity)
	if err != nil {
		e.logger.Warn("enrollment rejected: bad CSR",
			zap.String("hostname", req.Hostname),
			zap.String("peer", peerIP),
			zap.Error(err),
		)
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}

	now := time.Now().UTC()
	host := &event.Host{
		ID:            hostID,
		Hostname:      req.Hostname,
		IPAddress:     peerIP,
		AgentVersion:  req.AgentVersion,
		OSInfo:        req.OsInfo,
		Status:        event.HostOnline,
		EnrolledAt:    now,
		LastHeartbeat: now,
	}
	consume := ""
	if match.SingleUse {
		consume = match.Fingerprint
	}
	if err := e.store.EnrollHost(ctx, host, match.Name, consume); err != nil {
		if errors.Is(err, hcrypto.ErrTokenUsed) {
			e.logger.Warn("enrollment rejected",
				zap.String("hostname", req.Hostname),
				zap.String("peer", peerIP),
				zap.String("token", match.Name),
				zap.Error(err),
			)
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		e.logger.Error("failed to register host during enrollment",
			zap.String("hostname", req.Hostname),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "failed to register host")
	}

	e.logger.Info("bus enrolled",
		zap.String("host_id", hostID),
		zap.String("hostname", req.Hostname),
		zap.String("peer", peerIP),
		zap.String("token", match.Name),
		zap.String("agent_version", req.AgentVersion),
	)

	return &hookmonv1.EnrollResponse{
		HostId:     hostID,
		SignedCert: certPEM,
		CaCert:     e.ca.CertPEM(),
	}, nil
}

// peerIP returns the IP address of the RPC's peer, or "".
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
