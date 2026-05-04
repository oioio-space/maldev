// Package log provides build-tag gated structured logging for maldev.
//
// In the default (release) build, all logging functions are no-ops that
// compile to nothing — no format strings, no function calls, no
// indicators in the binary. This is critical for operational security
// because strings like "checking Windows version" would be visible via
// `strings binary.exe`.
//
// To enable logging during development, build with:
//
//	go build -tags debug ./...
//
// When debug is enabled, logging uses log/slog with a configurable handler.
//
// Usage:
//
//	logger := log.New(handler)   // debug build: real logger, release: no-op
//	logger.Info("msg", "k", v)   // debug build: outputs, release: eliminated
//
// For packages that accept an optional logger from callers:
//
//	func DoWork(l *log.Logger) {
//	    if l == nil {
//	        l = log.Nop()
//	    }
//	    l.Info("working")
//	}
//
// # Required privileges
//
// unprivileged. Release build is a no-op (zero call surface).
// Debug build wraps stdlib `log/slog` — handler-defined output
// (stderr by default), inheriting whatever permission the
// chosen sink demands.
//
// # Platform
//
// Cross-platform. Stdlib `log/slog` only.
package log
