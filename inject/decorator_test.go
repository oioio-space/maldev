package inject

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockInjector struct {
	called    bool
	shellcode []byte
	err       error
}

func (m *mockInjector) Inject(sc []byte) error {
	m.called = true
	m.shellcode = make([]byte, len(sc))
	copy(m.shellcode, sc)
	return m.err
}

func TestWithValidation_EmptyShellcode(t *testing.T) {
	mock := &mockInjector{}
	wrapped := WithValidation(mock)

	err := wrapped.Inject([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
	assert.False(t, mock.called, "inner injector should not be called for empty shellcode")
}

func TestWithValidation_ValidShellcode(t *testing.T) {
	mock := &mockInjector{}
	wrapped := WithValidation(mock)

	sc := []byte{0x90, 0x90, 0xCC}
	err := wrapped.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)
	assert.Equal(t, sc, mock.shellcode)
}

func TestWithCPUDelay(t *testing.T) {
	mock := &mockInjector{}
	// Use very small iterations so the test completes quickly.
	wrapped := WithCPUDelayConfig(CPUDelayConfig{
		MaxIterations:      100,
		FallbackIterations: 50,
	})(mock)

	sc := []byte{0xCC, 0xCC}
	err := wrapped.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)
	assert.Equal(t, sc, mock.shellcode)
}

func TestWithCPUDelayConfig_CustomIterations(t *testing.T) {
	mock := &mockInjector{}
	cfg := CPUDelayConfig{
		MaxIterations:      200,
		FallbackIterations: 100,
	}
	wrapped := WithCPUDelayConfig(cfg)(mock)

	sc := []byte{0x41, 0x42}
	err := wrapped.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)
	assert.Equal(t, sc, mock.shellcode)
}

func TestWithXOR_RandomKey(t *testing.T) {
	mock := &mockInjector{}
	wrapped := WithXOR(mock)

	sc := []byte{0x41, 0x42, 0x43, 0x44}
	err := wrapped.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)
	// The inner injector should receive XOR-encoded bytes, which differ
	// from the original (except in the astronomically unlikely case the
	// random key is 0x00).
	assert.NotEqual(t, sc, mock.shellcode, "shellcode should be XOR-encoded before reaching inner injector")
	assert.Equal(t, len(sc), len(mock.shellcode))
}

func TestWithXORKey_FixedKey(t *testing.T) {
	mock := &mockInjector{}
	key := byte(0x41)
	wrapped := WithXORKey(key)(mock)

	sc := []byte{0x00, 0x01, 0x02, 0x03}
	err := wrapped.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)

	// Verify deterministic XOR encoding.
	expected := make([]byte, len(sc))
	for i, b := range sc {
		expected[i] = b ^ key
	}
	assert.Equal(t, expected, mock.shellcode)
}

func TestChain_Order(t *testing.T) {
	// Track the order middlewares are applied by recording calls.
	var order []string

	mwA := func(inner Injector) Injector {
		return &orderTracker{inner: inner, name: "A", order: &order}
	}
	mwB := func(inner Injector) Injector {
		return &orderTracker{inner: inner, name: "B", order: &order}
	}

	base := &mockInjector{}
	chained := Chain(base, mwA, mwB)

	err := chained.Inject([]byte{0x90})
	require.NoError(t, err)
	// mwA is outermost, so it executes first; mwB is next; then base.
	assert.Equal(t, []string{"A", "B"}, order)
	assert.True(t, base.called)
}

func TestChain_Empty(t *testing.T) {
	mock := &mockInjector{}
	chained := Chain(mock)

	sc := []byte{0xCC}
	err := chained.Inject(sc)
	require.NoError(t, err)
	assert.True(t, mock.called)
	assert.Equal(t, sc, mock.shellcode)
}

func TestChain_InnerError(t *testing.T) {
	innerErr := errors.New("injection failed")
	mock := &mockInjector{err: innerErr}
	chained := Chain(mock, WithValidation)

	err := chained.Inject([]byte{0x90})
	assert.ErrorIs(t, err, innerErr)
}

// orderTracker is a helper injector that records when it is invoked.
type orderTracker struct {
	inner Injector
	name  string
	order *[]string
}

func (o *orderTracker) Inject(sc []byte) error {
	*o.order = append(*o.order, o.name)
	return o.inner.Inject(sc)
}
