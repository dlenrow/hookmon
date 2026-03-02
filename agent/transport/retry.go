package transport

import (
	"context"
	"math"
	"time"

	"go.uber.org/zap"
)

// RetryConfig controls exponential backoff reconnection behavior.
type RetryConfig struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	MaxAttempts  int // 0 = unlimited
}

// DefaultRetryConfig returns sensible retry defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialDelay: 1 * time.Second,
		MaxDelay:     60 * time.Second,
		Multiplier:   2.0,
		MaxAttempts:  0,
	}
}

// RetryLoop calls connectFn repeatedly with exponential backoff until it
// succeeds or the context is cancelled.
func RetryLoop(ctx context.Context, cfg RetryConfig, logger *zap.Logger, connectFn func(context.Context) error) error {
	delay := cfg.InitialDelay
	attempt := 0

	for {
		attempt++
		if err := connectFn(ctx); err == nil {
			return nil
		} else {
			logger.Warn("connection attempt failed",
				zap.Int("attempt", attempt),
				zap.Duration("next_retry", delay),
				zap.Error(err),
			)
		}

		if cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts {
			return context.DeadlineExceeded
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		delay = time.Duration(math.Min(
			float64(delay)*cfg.Multiplier,
			float64(cfg.MaxDelay),
		))
	}
}
