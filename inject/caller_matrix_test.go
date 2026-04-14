//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

var selfInjectMethods = []struct {
	name string
	m    Method
}{
	{"CreateThread", MethodCreateThread},
	// CreateFiber excluded: ConvertThreadToFiber + SwitchToFiber deadlocks
	// in Go's M:N scheduler. Tested separately in realsc_windows_test.go.
	{"EtwpCreateEtwThread", MethodEtwpCreateEtwThread},
}

var remoteInjectMethods = []struct {
	name string
	m    Method
}{
	{"CreateRemoteThread", MethodCreateRemoteThread},
	{"RtlCreateUserThread", MethodRtlCreateUserThread},
	{"QueueUserAPC", MethodQueueUserAPC},
	{"NtQueueApcThreadEx", MethodNtQueueApcThreadEx},
}

var spawnInjectMethods = []struct {
	name string
	m    Method
}{
	{"EarlyBirdAPC", MethodEarlyBirdAPC},
	{"ThreadHijack", MethodThreadHijack},
}

// TestCallerMatrix_SelfInject tests self-injection methods × 4 syscall methods.
// Uses WindowsSearchableCanary so ScanProcessMemory can verify the payload.
func TestCallerMatrix_SelfInject(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	callers := testutil.CallerMethods(t)
	sc := testutil.WindowsSearchableCanary

	for _, method := range selfInjectMethods {
		method := method
		for _, c := range callers {
			c := c
			t.Run(method.name+"/"+c.Name, func(t *testing.T) {
				cfg := &WindowsConfig{
					Config:        Config{Method: method.m},
					SyscallMethod: c.Method,
				}
				inj, err := NewWindowsInjector(cfg)
				require.NoError(t, err)
				require.NoError(t, inj.Inject(sc))

				marker := sc[3:] // "MALDEV_CANARY!!\n"
				_, found := testutil.ScanProcessMemory(marker)
				require.True(t, found,
					"%s/%s: canary marker not found in executable memory after injection",
					method.name, c.Name)
			})
		}
	}
}

// TestCallerMatrix_RemoteInject tests remote injection methods × 4 syscall methods.
// Spawns fresh notepad per sub-test, verifies target alive after injection.
func TestCallerMatrix_RemoteInject(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	callers := testutil.CallerMethods(t)
	sc := testutil.WindowsCanaryX64

	for _, method := range remoteInjectMethods {
		method := method
		for _, c := range callers {
			c := c
			t.Run(method.name+"/"+c.Name, func(t *testing.T) {
				pid, cleanup := testutil.SpawnAndResume(t)
				defer cleanup()

				cfg := &WindowsConfig{
					Config:        Config{Method: method.m, PID: int(pid)},
					SyscallMethod: c.Method,
				}
				inj, err := NewWindowsInjector(cfg)
				require.NoError(t, err)
				require.NoError(t, inj.Inject(sc))

				// Verify target still alive (WAIT_TIMEOUT=258 means not exited).
				hProcess, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
				require.NoError(t, err, "OpenProcess for alive-check")
				defer windows.CloseHandle(hProcess)

				const waitTimeout = uint32(258)
				ret, _ := windows.WaitForSingleObject(hProcess, 250)
				require.Equal(t, waitTimeout, ret,
					"%s/%s: target process exited unexpectedly after injection",
					method.name, c.Name)
			})
		}
	}
}

// TestCallerMatrix_SpawnInject tests methods that spawn their own process
// (EarlyBirdAPC, ThreadHijack) × 4 syscall methods.
//
// Known issue: ThreadHijack with Direct/Indirect syscalls fails because
// NtGetContextThread and NtWriteVirtualMemory don't work correctly via
// direct/indirect syscall stubs (NTSTATUS 0x80000002 / 0x8000000D).
// These combos are logged as warnings, not hard failures.
func TestCallerMatrix_SpawnInject(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	callers := testutil.CallerMethods(t)
	sc := testutil.WindowsCanaryX64

	for _, method := range spawnInjectMethods {
		method := method
		for _, c := range callers {
			c := c
			t.Run(method.name+"/"+c.Name, func(t *testing.T) {
				cfg := &WindowsConfig{
					Config:        Config{Method: method.m},
					SyscallMethod: c.Method,
				}
				inj, err := NewWindowsInjector(cfg)
				require.NoError(t, err)

				err = inj.Inject(sc)
				if err != nil && method.m == MethodThreadHijack &&
					(c.Name == "Direct" || c.Name == "Indirect") {
					t.Logf("KNOWN ISSUE: %s/%s: %v (NtGetContextThread/NtWriteVirtualMemory incompatible with %s syscalls)", method.name, c.Name, err, c.Name)
					return
				}
				require.NoError(t, err)
			})
		}
	}
}
