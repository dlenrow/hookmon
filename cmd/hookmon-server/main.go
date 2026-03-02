package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/version"
	"github.com/dlenrow/hookmon/server"
)

func main() {
	grpcAddr := flag.String("grpc-addr", ":9443", "gRPC listen address")
	httpAddr := flag.String("http-addr", ":8443", "HTTP API listen address")
	dbURL := flag.String("db", "postgres://hookmon:hookmon@localhost:5432/hookmon?sslmode=disable", "PostgreSQL connection string")
	apiTokens := flag.String("api-tokens", "", "comma-separated API tokens")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	tlsCA := flag.String("tls-ca", "", "TLS CA certificate file")
	insecure := flag.Bool("insecure", false, "disable TLS (development only)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting hookmon-server", zap.String("version", version.Version))

	var tokens []string
	if *apiTokens != "" {
		tokens = strings.Split(*apiTokens, ",")
	}

	cfg := server.Config{
		GRPCAddr:    *grpcAddr,
		HTTPAddr:    *httpAddr,
		DatabaseURL: *dbURL,
		APITokens:   tokens,
		TLS: server.TLSConfig{
			CertFile: *tlsCert,
			KeyFile:  *tlsKey,
			CAFile:   *tlsCA,
			Insecure: *insecure,
		},
		Watchdog: server.DefaultWatchdogConfig(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	srv := server.New(cfg, logger)
	if err := srv.Run(ctx); err != nil {
		logger.Fatal("server exited with error", zap.Error(err))
	}
}
