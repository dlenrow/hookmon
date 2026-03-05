package smoketest

import (
	"testing"

	"go.uber.org/zap"
)

func noopLogger(t *testing.T) *zap.Logger {
	t.Helper()
	l, _ := zap.NewDevelopment()
	return l
}
