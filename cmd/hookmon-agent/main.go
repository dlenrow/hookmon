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
	"github.com/dlenrow/hookmon/pkg/version"
)

func main() {
	configPath := flag.String("config", "/etc/hookmon/agent.yaml", "path to agent config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	consoleMode := flag.Bool("console", false, "print events to stdout as JSON (no server connection)")
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

	logger.Info("starting hookmon-agent", zap.String("version", version.Version), zap.Bool("console", *consoleMode))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Warn("using default config", zap.Error(err))
		cfg = config.DefaultConfig()
	}
	cfg.ConsoleMode = *consoleMode

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
		logger.Fatal("agent exited with error", zap.Error(err))
	}
}
