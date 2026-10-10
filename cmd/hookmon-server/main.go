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
	configPath := flag.String("config", "", "server config file (YAML); default "+server.DefaultConfigPath+" if it exists")
	grpcAddr := flag.String("grpc-addr", ":9443", "gRPC (mutual TLS) listen address; overrides config")
	enrollAddr := flag.String("enroll-addr", ":9444", "enrollment listen address; overrides config")
	httpAddr := flag.String("http-addr", ":8443", "HTTP API listen address; overrides config")
	dbURL := flag.String("db", "postgres://hookmon:hookmon@localhost:5432/hookmon?sslmode=disable", "PostgreSQL connection string; overrides config")
	apiTokens := flag.String("api-tokens", "", "comma-separated API tokens; overrides config")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file; overrides config")
	tlsKey := flag.String("tls-key", "", "TLS private key file; overrides config")
	tlsCA := flag.String("tls-ca", "", "CA certificate that verifies bus certificates; overrides config")
	tlsCAKey := flag.String("tls-ca-key", "", "CA private key that signs bus certificates at enrollment; overrides config")
	insecure := flag.Bool("insecure", false, "disable TLS (development only); overrides config")
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

	// Defaults, then the config file, then flags given on the command line.
	cfg := server.DefaultConfig()
	path := *configPath
	if path == "" {
		if _, err := os.Stat(server.DefaultConfigPath); err == nil {
			path = server.DefaultConfigPath
		}
	}
	if path != "" {
		cfg, err = server.LoadConfig(path)
		if err != nil {
			logger.Fatal("failed to load config", zap.Error(err))
		}
		logger.Info("loaded config", zap.String("path", path))
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "grpc-addr":
			cfg.GRPCAddr = *grpcAddr
		case "enroll-addr":
			cfg.EnrollAddr = *enrollAddr
		case "http-addr":
			cfg.HTTPAddr = *httpAddr
		case "db":
			cfg.Database.URL = *dbURL
		case "api-tokens":
			cfg.API.Tokens = nil
			if *apiTokens != "" {
				cfg.API.Tokens = strings.Split(*apiTokens, ",")
			}
		case "tls-cert":
			cfg.TLS.CertFile = *tlsCert
		case "tls-key":
			cfg.TLS.KeyFile = *tlsKey
		case "tls-ca":
			cfg.TLS.CAFile = *tlsCA
		case "tls-ca-key":
			cfg.TLS.CAKeyFile = *tlsCAKey
		case "insecure":
			cfg.TLS.Insecure = *insecure
		}
	})

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
