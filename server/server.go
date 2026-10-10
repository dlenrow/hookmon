package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/server/api"
	"github.com/dlenrow/hookmon/server/connectors"
	"github.com/dlenrow/hookmon/server/ingestion"
	"github.com/dlenrow/hookmon/server/policy"
	"github.com/dlenrow/hookmon/server/store"
)

// stopGrace bounds how long shutdown waits for open gRPC streams. Bus
// streams never end on their own, so GracefulStop alone would wait forever.
const stopGrace = 5 * time.Second

// ConnectorConfigs holds SIEM connector configurations.
type ConnectorConfigs struct {
	Syslog  *SyslogConfig
	Splunk  *SplunkConfig
	Elastic *ElasticConfig
	Webhook *WebhookConfig
	Kafka   *KafkaConfig
}

type SyslogConfig struct {
	Address  string
	Protocol string
}

type SplunkConfig struct {
	URL   string
	Token string
	Index string
}

type ElasticConfig struct {
	URL          string
	IndexPattern string
}

type WebhookConfig struct {
	URL     string
	Headers map[string]string
}

type KafkaConfig struct {
	Brokers []string
	Topic   string
}

// Server is the hookmon central server.
type Server struct {
	cfg        Config
	logger     *zap.Logger
	store      *store.Store
	grpcServer *grpc.Server
	httpServer *http.Server
	ingestion  *ingestion.IngestionServer
	policy     *policy.Engine
	alertMgr   *policy.AlertManager
	watchdog   *Watchdog
	connList   []connectors.Connector
	eventCh    chan *event.HookEvent

	// ready is closed once every listener is bound; the addresses below are
	// set by then.
	ready      chan struct{}
	grpcAddr   string
	enrollAddr string
	httpAddr   string
}

// New creates a new hookmon server.
func New(cfg Config, logger *zap.Logger) *Server {
	return &Server{
		cfg:     cfg,
		logger:  logger,
		eventCh: make(chan *event.HookEvent, 1024),
		ready:   make(chan struct{}),
	}
}

// Ready is closed once Run has bound every listener.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// GRPCAddr is the bound mutual-TLS gRPC address. Valid after Ready.
func (s *Server) GRPCAddr() string { return s.grpcAddr }

// EnrollAddr is the bound enrollment address, or "" if enrollment is off.
// Valid after Ready.
func (s *Server) EnrollAddr() string { return s.enrollAddr }

// HTTPAddr is the bound REST API address. Valid after Ready.
func (s *Server) HTTPAddr() string { return s.httpAddr }

// Run starts all server subsystems. Blocks until ctx is cancelled. It
// returns an error if the configuration is invalid or a listener cannot be
// bound.
func (s *Server) Run(ctx context.Context) error {
	if err := s.cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// Refuse plaintext unless it was asked for, before touching anything
	// else, so a server with no certificate never starts.
	if err := s.cfg.CheckTLS(); err != nil {
		return err
	}
	useTLS := s.cfg.UseTLS()
	var httpTLS *tls.Config
	if useTLS {
		var err error
		httpTLS, err = hcrypto.LoadHTTPServerTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load REST TLS: %w", err)
		}
	} else {
		s.logger.Warn("insecure mode: gRPC and REST run without TLS, and host IDs are taken from each message, so any host can report as any other; development only")
	}
	var dashboard *api.Dashboard
	if s.cfg.DashboardDir != "" {
		var err error
		dashboard, err = api.NewDashboard(s.cfg.DashboardDir)
		if err != nil {
			s.logger.Warn("not serving the dashboard", zap.String("dir", s.cfg.DashboardDir), zap.Error(err))
		}
	}

	tokens, err := hcrypto.NewTokenSet(s.cfg.Enrollment.Tokens)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	var ca *hcrypto.CA
	if tokens.Len() > 0 {
		ca, err = hcrypto.LoadCA(s.cfg.TLS.CAFile, s.cfg.TLS.CAKeyFile)
		if err != nil {
			return fmt.Errorf("load enrollment CA: %w", err)
		}
	}

	// Initialize store
	s.store, err = store.NewStore(ctx, s.cfg.Database.URL, s.logger)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer s.store.Close()

	if err := s.store.RunMigrations(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// Initialize connectors
	s.initConnectors()

	// Initialize policy engine
	s.policy = policy.NewEngine(s.logger)
	s.alertMgr = policy.NewAlertManager(s.logger, 5*time.Minute)

	// Load allowlist from DB
	entries, err := s.store.GetAllowlist(ctx)
	if err != nil {
		s.logger.Warn("failed to load allowlist", zap.Error(err))
	} else {
		s.policy.LoadAllowlist(entries)
	}

	// Initialize ingestion server
	var ingestConnectors []ingestion.Connector
	for _, c := range s.connList {
		ingestConnectors = append(ingestConnectors, c)
	}
	s.ingestion = ingestion.NewIngestionServer(ingestion.IngestionConfig{
		Store:        s.store,
		PolicyEngine: s.policy,
		Logger:       s.logger,
		Connectors:   ingestConnectors,
		RateLimiter:  ingestion.NewRateLimiter(100, 200),
		Insecure:     !useTLS,
	})

	// gRPC servers. The event stream needs a verified client certificate at
	// the TLS handshake. Enrollment has its own listener, where the server
	// authenticates itself but the bus, which has no certificate yet, does
	// not; only the Enroll RPC is registered there.
	var grpcOpts []grpc.ServerOption
	if useTLS {
		creds, err := hcrypto.LoadServerTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile, s.cfg.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("load TLS: %w", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}
	s.grpcServer = grpc.NewServer(grpcOpts...)
	hookmonv1.RegisterAgentServiceServer(s.grpcServer, s.ingestion)

	var enrollServer *grpc.Server
	if ca != nil {
		creds, err := hcrypto.LoadEnrollServerTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load enrollment TLS: %w", err)
		}
		enrollServer = grpc.NewServer(grpc.Creds(creds))
		hookmonv1.RegisterAgentServiceServer(enrollServer, ingestion.NewEnroller(ingestion.EnrollerConfig{
			Store:        s.store,
			Tokens:       tokens,
			CA:           ca,
			CertValidity: s.cfg.Enrollment.CertValidity,
			Logger:       s.logger,
		}))
	} else {
		s.logger.Info("no enrollment tokens configured; enrollment listener disabled")
	}

	// Bind every listener before starting anything, so a bad address fails
	// Run instead of leaving a server running without one of them.
	grpcLis, err := net.Listen("tcp", s.cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}
	listeners := []net.Listener{grpcLis}
	closeAll := func() {
		for _, l := range listeners {
			l.Close()
		}
	}
	var enrollLis net.Listener
	if enrollServer != nil {
		enrollLis, err = net.Listen("tcp", s.cfg.EnrollAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("listen enrollment: %w", err)
		}
		listeners = append(listeners, enrollLis)
		s.enrollAddr = enrollLis.Addr().String()
	}
	httpLis, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		closeAll()
		return fmt.Errorf("listen HTTP: %w", err)
	}
	s.grpcAddr = grpcLis.Addr().String()
	s.httpAddr = httpLis.Addr().String()
	close(s.ready)

	// Start subsystems
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serveGRPC(ctx, s.grpcServer, grpcLis); err != nil {
			s.logger.Error("gRPC server error", zap.Error(err))
		}
	}()

	if enrollServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serveGRPC(ctx, enrollServer, enrollLis); err != nil {
				s.logger.Error("enrollment server error", zap.Error(err))
			}
		}()
	}

	// REST API, WebSocket and dashboard, on TLS unless insecure.
	var dashHandler http.Handler
	if dashboard != nil {
		dashHandler = dashboard
	}
	apiSrv := api.NewServer(s.store, s.logger, s.ingestion.GetEventChannel())
	s.httpServer = &http.Server{Handler: apiSrv.Router(s.cfg.API.Tokens, dashHandler)}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serveHTTP(ctx, s.httpServer, httpLis, httpTLS); err != nil {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// Watchdog
	s.watchdog = NewWatchdog(s.cfg.Watchdog, s.store, &connectorAlertSink{connectors: s.connList}, s.logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.watchdog.Run(ctx)
	}()

	dashDir := ""
	if dashboard != nil {
		dashDir = dashboard.Dir()
	}
	s.logger.Info("hookmon server started",
		zap.String("grpc", s.grpcAddr),
		zap.String("enroll", s.enrollAddr),
		zap.String("http", s.httpAddr),
		zap.Bool("tls", useTLS),
		zap.String("dashboard", dashDir),
	)

	<-ctx.Done()
	s.shutdown()
	wg.Wait()
	return nil
}

// serveGRPC serves srv on lis until ctx is cancelled, then stops it,
// waiting at most stopGrace for open streams.
func serveGRPC(ctx context.Context, srv *grpc.Server, lis net.Listener) error {
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		done := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(stopGrace):
			srv.Stop()
		}
	}()
	err := srv.Serve(lis)
	<-stopped
	return err
}

// serveHTTP serves srv on lis until ctx is cancelled, over TLS when tlsCfg
// is non-nil and plain HTTP otherwise.
func serveHTTP(ctx context.Context, srv *http.Server, lis net.Listener, tlsCfg *tls.Config) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	var err error
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		err = srv.ServeTLS(lis, "", "")
	} else {
		err = srv.Serve(lis)
	}
	if err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) initConnectors() {
	if c := s.cfg.Connectors.Syslog; c != nil {
		conn, err := connectors.NewSyslogConnector(c.Address, c.Protocol, s.logger)
		if err == nil {
			s.connList = append(s.connList, conn)
		}
	}
	if c := s.cfg.Connectors.Splunk; c != nil {
		s.connList = append(s.connList, connectors.NewSplunkConnector(c.URL, c.Token, c.Index, s.logger))
	}
	if c := s.cfg.Connectors.Elastic; c != nil {
		s.connList = append(s.connList, connectors.NewElasticConnector(c.URL, c.IndexPattern, s.logger))
	}
	if c := s.cfg.Connectors.Webhook; c != nil {
		s.connList = append(s.connList, connectors.NewWebhookConnector(c.URL, c.Headers, s.logger))
	}
	if c := s.cfg.Connectors.Kafka; c != nil {
		conn, err := connectors.NewKafkaConnector(c.Brokers, c.Topic, s.logger)
		if err == nil {
			s.connList = append(s.connList, conn)
		}
	}
}

func (s *Server) shutdown() {
	for _, c := range s.connList {
		if err := c.Close(); err != nil {
			s.logger.Warn("connector close error", zap.Error(err))
		}
	}
}

// connectorAlertSink dispatches events to all connectors.
type connectorAlertSink struct {
	connectors []connectors.Connector
}

func (c *connectorAlertSink) Dispatch(evt *event.HookEvent) {
	for _, conn := range c.connectors {
		conn.Send(evt)
	}
}
