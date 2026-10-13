package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

// alertDedupWindow is how long a repeat of an alert is kept from the alert
// connectors.
const alertDedupWindow = 5 * time.Minute

// connectorDrainTimeout bounds how long shutdown waits for the connector
// queues to drain.
const connectorDrainTimeout = 5 * time.Second

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
	dispatcher *connectors.Dispatcher

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
		cfg:    cfg,
		logger: logger,
		ready:  make(chan struct{}),
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

	// SIEM connectors, before the database, so one that cannot start (a
	// syslog receiver or Kafka broker that cannot be reached, a failed
	// Elasticsearch ILM setup) fails startup at once. Each has its own
	// queue and worker; ingestion and the watchdog only enqueue.
	s.alertMgr = policy.NewAlertManager(s.logger, alertDedupWindow)
	s.dispatcher, err = connectors.New(ctx, s.cfg.Connectors, s.alertMgr, s.logger)
	if err != nil {
		return fmt.Errorf("start connectors: %w", err)
	}
	// Run returns only after every stream and the watchdog have stopped,
	// so this drains the queues once nothing can add to them.
	defer func() {
		drainCtx, cancel := context.WithTimeout(context.Background(), connectorDrainTimeout)
		defer cancel()
		if err := s.dispatcher.Close(drainCtx); err != nil {
			s.logger.Warn("connector close error", zap.Error(err))
		}
	}()

	// Initialize store
	s.store, err = store.NewStore(ctx, s.cfg.Database.URL, s.logger)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer s.store.Close()

	if err := s.store.RunMigrations(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// Initialize policy engine. It reads the allowlist and the learning
	// windows from the database now, after every policy write through the
	// API, and on SIGHUP; learning mode records candidates in the database.
	s.policy = policy.NewEngine(s.logger)
	s.policy.SetSource(s.store)
	s.policy.SetCandidateSink(s.store)
	if err := s.policy.Reload(ctx); err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	// Initialize ingestion server. Every stored event goes to the
	// dispatcher, which routes it to the connectors that take it.
	s.ingestion = ingestion.NewIngestionServer(ingestion.IngestionConfig{
		Store:        s.store,
		PolicyEngine: s.policy,
		Logger:       s.logger,
		Connectors:   []ingestion.Connector{s.dispatcher},
		StatusSink:   s.dispatcher,
		RateLimiter:  ingestion.NewRateLimiter(100, 200),
		Insecure:     !useTLS,
	})

	// REST API, WebSocket and dashboard. The hub fans every processed event
	// out to each WebSocket client; it starts with the listeners below.
	hub := api.NewHub(api.DefaultSubscriberBuffer)
	apiSrv := api.NewServer(s.store, s.logger, hub)
	apiSrv.SetPolicyReloader(s.policy)
	if err := apiSrv.SetAllowedOrigins(s.cfg.API.AllowedOrigins); err != nil {
		return fmt.Errorf("config: api.allowed_origins: %w", err)
	}
	apiSrv.SetSettingsSource(s.settings)

	// gRPC servers. The event stream needs a verified client certificate at
	// the TLS handshake. Enrollment has its own listener, where the server
	// authenticates itself but the bus, which has no certificate yet, does
	// not; only the Enroll RPC is registered there.
	// A panic in a handler fails that call or stream, not the server.
	grpcOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(ingestion.RecoveryUnaryInterceptor(s.logger)),
		grpc.ChainStreamInterceptor(ingestion.RecoveryStreamInterceptor(s.logger)),
	}
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
		enrollServer = grpc.NewServer(grpc.Creds(creds),
			grpc.ChainUnaryInterceptor(ingestion.RecoveryUnaryInterceptor(s.logger)),
			grpc.ChainStreamInterceptor(ingestion.RecoveryStreamInterceptor(s.logger)),
		)
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

	// SIGHUP rereads the policy. Registered before Ready, so a SIGHUP sent
	// once the server is up never takes the default action (exit).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
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
	// The hub fans every processed event out to each WebSocket client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hub.Run(ctx, s.ingestion.GetEventChannel())
	}()
	s.httpServer = newHTTPServer(apiSrv.Router(s.cfg.API.Tokens, dashHandler))
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serveHTTP(ctx, s.httpServer, httpLis, httpTLS); err != nil {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		reloadOnSignal(ctx, hup, s.policy.Reload, s.logger)
	}()

	// Watchdog: AGENT_OFFLINE goes to every connector and to the WebSocket
	// feed, as AGENT_RECOVERED does from the ingestion server.
	s.watchdog = NewWatchdog(s.cfg.Watchdog, s.store, statusFanout{s.dispatcher, s.ingestion}, s.logger)
	s.watchdog.SetShutdownChecker(s.ingestion)
	s.watchdog.SetMarkerChecker(s.ingestion)
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
		zap.Int("connectors", s.dispatcher.Len()),
	)

	<-ctx.Done()
	wg.Wait()
	return nil
}

// HTTP server timeouts. ReadHeaderTimeout bounds a client that opens a
// connection and sends its headers slowly (Slowloris); ReadTimeout bounds
// the whole request, whose body is at most 64 KiB; IdleTimeout closes
// keep-alive connections nobody uses. There is no WriteTimeout, because the
// WebSocket feed is a response that lasts as long as the dashboard is open;
// the hub closes a client that stops reading.
const (
	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 30 * time.Second
	httpIdleTimeout       = 120 * time.Second
	httpMaxHeaderBytes    = 64 << 10
)

// newHTTPServer returns the REST API, WebSocket and dashboard server for
// handler, with the timeouts above.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

// statusFanout sends a host status event the server raised (AGENT_OFFLINE)
// to every connector and to the WebSocket feed.
type statusFanout struct {
	connectors AlertSink
	feed       interface{ Publish(*event.HookEvent) }
}

func (f statusFanout) Dispatch(evt *event.HookEvent) {
	f.connectors.Dispatch(evt)
	f.feed.Publish(evt)
}

// reloadOnSignal calls reload for every signal on sig until ctx is done.
func reloadOnSignal(ctx context.Context, sig <-chan os.Signal, reload func(context.Context) error, logger *zap.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case got := <-sig:
			if err := reload(ctx); err != nil {
				logger.Error("policy reload failed; keeping the previous policy",
					zap.String("signal", got.String()), zap.Error(err))
				continue
			}
			logger.Info("policy reloaded", zap.String("signal", got.String()))
		}
	}
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
