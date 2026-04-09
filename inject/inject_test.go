package inject

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMethodValid(t *testing.T) {
	for _, m := range AvailableMethods() {
		m := m
		t.Run(string(m), func(t *testing.T) {
			err := ValidateMethod(m)
			assert.NoError(t, err, "method %q should be valid on this platform", m)
		})
	}
}

func TestValidateMethodInvalid(t *testing.T) {
	err := ValidateMethod("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestAvailableMethodsNotEmpty(t *testing.T) {
	methods := AvailableMethods()
	assert.NotEmpty(t, methods, "AvailableMethods must return at least one method on any supported platform")
}

func TestDefaultMethod(t *testing.T) {
	m := DefaultMethod()
	require.NotEmpty(t, m, "DefaultMethod must not return an empty string")
	err := ValidateMethod(m)
	assert.NoError(t, err, "DefaultMethod %q must be in AvailableMethods", m)
}

func TestFallbackChainContainsMethod(t *testing.T) {
	// Use a method that is available on the current platform.
	methods := AvailableMethods()
	require.NotEmpty(t, methods)

	target := methods[0]
	chain := FallbackChain(target)

	assert.NotEmpty(t, chain, "FallbackChain must return a non-empty slice")
	assert.Equal(t, target, chain[0], "FallbackChain must start with the requested method")
}

func TestConfigValidate(t *testing.T) {
	// DefaultMethodForStage returns a self-injection method on every platform
	// (CreateThread on Windows, ProcMem on Linux) — neither requires a PID.
	cfg := &Config{
		Method: DefaultMethodForStage(),
	}
	err := cfg.Validate()
	assert.NoError(t, err, "Config with DefaultMethodForStage should pass Validate without a PID")
}

func TestConfigValidateInvalidMethod(t *testing.T) {
	cfg := &Config{
		Method: "bad",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestEtwpCreateEtwThreadInAvailableMethods(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only injection method")
	}
	methods := AvailableMethods()
	assert.Contains(t, methods, MethodEtwpCreateEtwThread,
		"AvailableMethods should include MethodEtwpCreateEtwThread")
}

func TestNtQueueApcThreadExInAvailableMethods(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only injection method")
	}
	methods := AvailableMethods()
	assert.Contains(t, methods, MethodNtQueueApcThreadEx,
		"AvailableMethods should include MethodNtQueueApcThreadEx")
}

func TestEtwpCreateEtwThreadFallbackChain(t *testing.T) {
	chain := FallbackChain(MethodEtwpCreateEtwThread)
	require.NotEmpty(t, chain)
	assert.Equal(t, MethodEtwpCreateEtwThread, chain[0])
}

func TestNtQueueApcThreadExFallbackChain(t *testing.T) {
	chain := FallbackChain(MethodNtQueueApcThreadEx)
	require.NotEmpty(t, chain)
	assert.Equal(t, MethodNtQueueApcThreadEx, chain[0])
}

func TestDefaultMethodForStage(t *testing.T) {
	m := DefaultMethodForStage()
	require.NotEmpty(t, m, "DefaultMethodForStage must return a non-empty method")
	err := ValidateMethod(m)
	assert.NoError(t, err, "DefaultMethodForStage %q must be a valid method", m)
}

func TestNewStats(t *testing.T) {
	method := DefaultMethod()
	size := 4096
	pid := 1234

	s := NewStats(method, size, pid)
	require.NotNil(t, s, "NewStats must return a non-nil *Stats")
	assert.Equal(t, method, s.Method)
	assert.Equal(t, size, s.ShellcodeSize)
	assert.Equal(t, pid, s.TargetPID)
	assert.False(t, s.StartTime.IsZero(), "StartTime should be set")
	assert.False(t, s.Success, "Success should default to false")
	assert.Nil(t, s.Error, "Error should default to nil")
}
