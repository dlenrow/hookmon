package server

import (
	"context"
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

// Config holds the hookmon-server configuration.
type Config struct {
	GRPCAddr     string
	HTTPAddr     string
	DatabaseURL  string
	APITokens    []string
	TLS          TLSConfig
	Watchdog     WatchdogConfig
	Connectors   ConnectorConfigs
}

// TLSConfig holds server TLS settings.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Insecure bool
}

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
}

// New creates a new hookmon server.
func New(cfg Config, logger *zap.Logger) *Server {
	return &Server{
		cfg:     cfg,
		logger:  logger,
		eventCh: make(chan *event.HookEvent, 1024),
	}
}

// Run starts all server subsystems. Blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// Initialize store
	var err error
	s.store, err = store.NewStore(ctx, s.cfg.DatabaseURL, s.logger)
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
	})

	// Start subsystems
	var wg sync.WaitGroup

	// gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runGRPC(ctx); err != nil {
			s.logger.Error("gRPC server error", zap.Error(err))
		}
	}()

	// HTTP API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runHTTP(ctx); err != nil {
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

	s.logger.Info("hookmon server started",
		zap.String("grpc", s.cfg.GRPCAddr),
		zap.String("http", s.cfg.HTTPAddr),
	)

	<-ctx.Done()
	s.shutdown()
	wg.Wait()
	return nil
}

func (s *Server) runGRPC(ctx context.Context) error {
	var opts []grpc.ServerOption

	if !s.cfg.TLS.Insecure && s.cfg.TLS.CertFile != "" {
		creds, err := hcrypto.LoadServerTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile, s.cfg.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("load TLS: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	s.grpcServer = grpc.NewServer(opts...)
	hookmonv1.RegisterAgentServiceServer(s.grpcServer, s.ingestion)

	lis, err := net.Listen("tcp", s.cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}

	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()

	return s.grpcServer.Serve(lis)
}

func (s *Server) runHTTP(ctx context.Context) error {
	apiSrv := api.NewServer(s.store, s.logger, s.ingestion.GetEventChannel())
	router := apiSrv.Router(s.cfg.APITokens)

	s.httpServer = &http.Server{
		Addr:    s.cfg.HTTPAddr,
		Handler: router,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
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
