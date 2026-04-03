//go:build debug

// Debug build: real structured logging via log/slog.
package log

import (
	"io"
	"os"

	slog "github.com/oioio-space/maldev/internal/compat/slog"
)

// Logger wraps slog.Logger in debug builds.
type Logger struct {
	inner *slog.Logger
}

// New creates a Logger from an slog.Handler. If handler is nil,
// logs to stderr with text format.
func New(handler any) *Logger {
	if h, ok := handler.(slog.Handler); ok {
		return &Logger{inner: slog.New(h)}
	}
	// Default: text to stderr.
	return &Logger{inner: slog.New(slog.NewTextHandler(os.Stderr, nil))}
}

// Nop returns a Logger that discards all output.
func Nop() *Logger {
	return &Logger{inner: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))}
}

// Info logs at INFO level.
func (l *Logger) Info(msg string, args ...any) { l.inner.Info(msg, args...) }

// Warn logs at WARN level.
func (l *Logger) Warn(msg string, args ...any) { l.inner.Warn(msg, args...) }

// Error logs at ERROR level.
func (l *Logger) Error(msg string, args ...any) { l.inner.Error(msg, args...) }

// Debug logs at DEBUG level.
func (l *Logger) Debug(msg string, args ...any) { l.inner.Debug(msg, args...) }

// Enabled returns true in debug builds.
func (*Logger) Enabled() bool { return true }
