//go:build !debug

// Release build: all methods are no-ops. The compiler inlines and eliminates
// them entirely — no format strings or call overhead in the binary.
package log

// Logger is a no-op logger in release builds.
type Logger struct{}

// New returns a no-op Logger. The handler parameter is ignored.
func New(_ any) *Logger { return &Logger{} }

// Nop returns a no-op Logger.
func Nop() *Logger { return &Logger{} }

// Info is a no-op in release builds.
func (*Logger) Info(_ string, _ ...any) {}

// Warn is a no-op in release builds.
func (*Logger) Warn(_ string, _ ...any) {}

// Error is a no-op in release builds.
func (*Logger) Error(_ string, _ ...any) {}

// Debug is a no-op in release builds.
func (*Logger) Debug(_ string, _ ...any) {}

// Enabled always returns false in release builds.
func (*Logger) Enabled() bool { return false }
