//go:build !linux

package enrichment

import "github.com/dlenrow/hookmon/pkg/event"

// Enricher is a no-op on non-Linux platforms.
type Enricher struct{}

// NewEnricher returns a no-op Enricher.
func NewEnricher() *Enricher { return &Enricher{} }

// Enrich is a no-op on non-Linux platforms.
func (*Enricher) Enrich(*event.HookEvent) {}
