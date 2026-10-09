//go:build !linux

package agent

import (
	"time"

	"go.uber.org/zap"
)

// hookProber is a no-op off Linux, where no eBPF sensor starts.
type hookProber struct{}

func newHookProber(string, *zap.Logger) *hookProber { return &hookProber{} }

func (p *hookProber) probe([]string) map[string]string { return nil }

var processStart = time.Now()

func monotonicNow() (uint64, error) { return uint64(time.Since(processStart)), nil }
