//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func TestBuild_MissingMethod(t *testing.T) {
	_, err := Build().Create()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "method is required")
}

func TestBuild_RemoteWithoutPID(t *testing.T) {
	remoteMethods := []Method{
		MethodCreateRemoteThread,
		MethodQueueUserAPC,
		MethodRtlCreateUserThread,
		MethodNtQueueApcThreadEx,
	}
	for _, m := range remoteMethods {
		t.Run(string(m), func(t *testing.T) {
			_, err := Build().Method(m).Create()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "requires a target PID")
		})
	}
}

func TestBuild_SelfInjectNoPID(t *testing.T) {
	selfMethods := []Method{
		MethodCreateThread,
		MethodCreateFiber,
		MethodEtwpCreateEtwThread,
	}
	for _, m := range selfMethods {
		t.Run(string(m), func(t *testing.T) {
			inj, err := Build().Method(m).Create()
			require.NoError(t, err)
			assert.NotNil(t, inj)
		})
	}
}

func TestBuild_ValidRemote(t *testing.T) {
	inj, err := Build().
		Method(MethodCreateRemoteThread).
		TargetPID(1234).
		Create()
	require.NoError(t, err)
	assert.NotNil(t, inj)
}

func TestBuild_WithMiddleware(t *testing.T) {
	called := false
	mw := func(inner Injector) Injector {
		called = true
		return inner
	}

	inj, err := Build().
		Method(MethodCreateThread).
		Use(mw).
		Create()
	require.NoError(t, err)
	assert.NotNil(t, inj)
	assert.True(t, called, "middleware should have been invoked during Create")
}

func TestNeedsRemotePID(t *testing.T) {
	tests := []struct {
		method Method
		want   bool
	}{
		{MethodCreateRemoteThread, true},
		{MethodQueueUserAPC, true},
		{MethodRtlCreateUserThread, true},
		{MethodNtQueueApcThreadEx, true},
		{MethodCreateThread, false},
		{MethodCreateFiber, false},
		{MethodEtwpCreateEtwThread, false},
		{MethodEarlyBirdAPC, false},
		{MethodThreadHijack, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			assert.Equal(t, tt.want, needsRemotePID(tt.method))
		})
	}
}

func TestBuild_SyscallMethods(t *testing.T) {
	tests := []struct {
		name   string
		build  func() *InjectorBuilder
		want   wsyscall.Method
	}{
		{
			name:  "default is WinAPI",
			build: func() *InjectorBuilder { return Build() },
			want:  wsyscall.MethodWinAPI,
		},
		{
			name:  "WinAPI",
			build: func() *InjectorBuilder { return Build().WinAPI() },
			want:  wsyscall.MethodWinAPI,
		},
		{
			name:  "NativeAPI",
			build: func() *InjectorBuilder { return Build().NativeAPI() },
			want:  wsyscall.MethodNativeAPI,
		},
		{
			name:  "DirectSyscalls",
			build: func() *InjectorBuilder { return Build().DirectSyscalls() },
			want:  wsyscall.MethodDirect,
		},
		{
			name:  "IndirectSyscalls",
			build: func() *InjectorBuilder { return Build().IndirectSyscalls() },
			want:  wsyscall.MethodIndirect,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.build()
			assert.Equal(t, tt.want, b.syscallMethod)
		})
	}
}
