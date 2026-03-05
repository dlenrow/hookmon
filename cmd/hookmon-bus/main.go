package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent"
	"github.com/dlenrow/hookmon/agent/config"
	"github.com/dlenrow/hookmon/agent/sensors"
	"github.com/dlenrow/hookmon/pkg/version"
)

func main() {
	configPath := flag.String("config", "/etc/hookmon/bus.yaml", "path to sensor bus config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	consoleMode := flag.Bool("console", false, "print events to stdout as JSON (no server connection)")
	lokiURL := flag.String("loki-url", "", "Loki push URL (e.g. http://localhost:3100); empty disables")
	statusPort := flag.Int("status-port", 0, "port for /status and /metrics endpoints; overrides config")
	scanRpath := flag.String("scan-rpath", "", "scan a directory for ELF RPATH issues and exit (e.g. /usr/bin)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if *scanRpath != "" {
		data, err := sensors.ScanDirectoryJSON(*scanRpath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan-rpath error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		os.Exit(0)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting hookmon-bus", zap.String("version", version.Version), zap.Bool("console", *consoleMode))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Warn("using default config", zap.Error(err))
		cfg = config.DefaultConfig()
	}
	cfg.ConsoleMode = *consoleMode
	if *lokiURL != "" {
		cfg.LokiURL = *lokiURL
	}
	if *statusPort > 0 {
		cfg.StatusPort = *statusPort
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	a := agent.New(cfg, logger)
	if err := a.Run(ctx); err != nil {
		logger.Fatal("sensor bus exited with error", zap.Error(err))
	}
}
