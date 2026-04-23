package inject

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegion_ZeroValue(t *testing.T) {
	var r Region
	assert.Equal(t, uintptr(0), r.Addr)
	assert.Equal(t, uintptr(0), r.Size)
}

// fakeSelfInjector is a minimal SelfInjector stub used to verify that the
// decorators forward InjectedRegion through to their inner injector.
type fakeSelfInjector struct {
	region  Region
	hasReg  bool
	injectN int
}

func (f *fakeSelfInjector) Inject(shellcode []byte) error {
	f.injectN++
	return nil
}

func (f *fakeSelfInjector) InjectedRegion() (Region, bool) {
	return f.region, f.hasReg
}

// fakeInjector is a plain Injector (not SelfInjector) — decorators wrapping
// it must return (Region{}, false) from InjectedRegion.
type fakeInjector struct{ err error }

func (f *fakeInjector) Inject(shellcode []byte) error { return f.err }

func TestSelfInjector_DecoratorsForwardRegion_FromSelfInner(t *testing.T) {
	inner := &fakeSelfInjector{
		region: Region{Addr: 0xDEAD0000, Size: 4096},
		hasReg: true,
	}

	// Each decorator independently and via Chain.
	cases := []struct {
		name string
		inj  Injector
	}{
		{"validating", WithValidation(inner)},
		{"cpuDelay", WithCPUDelayConfig(CPUDelayConfig{MaxIterations: 1, FallbackIterations: 1})(inner)},
		{"xor", WithXOR(inner)},
		{"chain", Chain(inner,
			WithValidation,
			WithCPUDelayConfig(CPUDelayConfig{MaxIterations: 1, FallbackIterations: 1}),
			WithXOR,
		)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			si, ok := tc.inj.(SelfInjector)
			require.True(t, ok, "decorator must satisfy SelfInjector")
			r, hasReg := si.InjectedRegion()
			assert.True(t, hasReg)
			assert.Equal(t, uintptr(0xDEAD0000), r.Addr)
			assert.Equal(t, uintptr(4096), r.Size)
		})
	}
}

func TestSelfInjector_DecoratorsForwardRegion_FromPlainInner(t *testing.T) {
	// Inner is a plain Injector with no InjectedRegion method. Decorators
	// still satisfy SelfInjector (static shape) but must report no region.
	inner := &fakeInjector{}

	wrapped := WithValidation(WithXOR(inner))

	si, ok := wrapped.(SelfInjector)
	require.True(t, ok)
	r, hasReg := si.InjectedRegion()
	assert.False(t, hasReg)
	assert.Equal(t, Region{}, r)
}

func TestSelfInjector_ValidatingRejectsEmpty_KeepsRegionPassthrough(t *testing.T) {
	// Even when the decorator short-circuits Inject with an error, the
	// forwarded region should still reflect the inner's state (here: none).
	inner := &fakeSelfInjector{hasReg: false}
	v := WithValidation(inner)

	err := v.Inject(nil)
	require.Error(t, err)
	assert.Equal(t, 0, inner.injectN, "inner must not be called on validation failure")

	si := v.(SelfInjector)
	_, hasReg := si.InjectedRegion()
	assert.False(t, hasReg)
}

// TestPipeline_InjectedRegion exercises Pipeline.InjectedRegion: (zero,false)
// before Inject, populated after a successful Inject, unchanged after a
// failing Inject.
func TestPipeline_InjectedRegion(t *testing.T) {
	p := NewPipeline(
		memorySetupFunc(func(sc []byte) (uintptr, error) { return 0xBEEF0000, nil }),
		executorFunc(func(addr uintptr) error { return nil }),
	)

	r, ok := p.InjectedRegion()
	assert.False(t, ok, "InjectedRegion before Inject must be false")
	assert.Equal(t, Region{}, r)

	require.NoError(t, p.Inject([]byte{0x90, 0x90, 0x90}))
	r, ok = p.InjectedRegion()
	require.True(t, ok)
	assert.Equal(t, uintptr(0xBEEF0000), r.Addr)
	assert.Equal(t, uintptr(3), r.Size)

	// A later failing Inject must not clobber the region with a bogus one.
	pFail := NewPipeline(
		memorySetupFunc(func(sc []byte) (uintptr, error) { return 0, errors.New("boom") }),
		executorFunc(func(addr uintptr) error { return nil }),
	)
	require.Error(t, pFail.Inject([]byte{0x90}))
	_, ok = pFail.InjectedRegion()
	assert.False(t, ok, "failed Inject must not publish a region")
}

type memorySetupFunc func([]byte) (uintptr, error)

func (f memorySetupFunc) Setup(sc []byte) (uintptr, error) { return f(sc) }

type executorFunc func(uintptr) error

func (f executorFunc) Execute(addr uintptr) error { return f(addr) }
