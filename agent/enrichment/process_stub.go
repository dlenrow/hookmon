//go:build !linux

package enrichment

import "github.com/dlenrow/hookmon/pkg/event"

// EnrichProcess is a no-op on non-Linux platforms.
func EnrichProcess(_ *event.HookEvent) {}
