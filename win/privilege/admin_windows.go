//go:build windows

// Package privilege provides helpers for querying and obtaining elevated Windows privileges.
package privilege

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/impersonate"
	"github.com/oioio-space/maldev/win/token"
)

const (
	LOGON_WITH_PROFILE        uint32 = 0x1
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x2
)

// IsAdminGroupMember returns whether the current user is a member of the
// local Administrators group (SID S-1-5-32-544).
func IsAdminGroupMember() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}

	ids, err := u.GroupIds()
	if err != nil {
		return false, err
	}

	for _, v := range ids {
		if "S-1-5-32-544" == v {
			return true, nil
		}
	}

	return false, nil
}

// IsAdmin returns whether the process is running as administrator and whether
// the token is elevated.
func IsAdmin() (admin bool, elevated bool, err error) {
	var sid *windows.SID

	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false, false, err
	}
	defer windows.FreeSid(sid)

	var t windows.Token
	proc, _ := windows.GetCurrentProcess()
	if err = windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &t); err != nil {
		return false, false, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer t.Close()

	admin, err = t.IsMember(sid)
	if err != nil {
		return false, false, err
	}

	return admin, t.IsElevated(), nil
}

// ExecAs starts a program under the credentials of another user using Go's
// exec package with a SysProcAttr token. Equivalent to "RunAs".
//
// For domain accounts, uses LOGON32_LOGON_NEW_CREDENTIALS (type 9) which
// works without DC reachability and is suitable for process creation.
// For local accounts, uses LOGON32_LOGON_INTERACTIVE (type 2).
//
// Returns the started Cmd so the caller can call cmd.Wait() to avoid
// leaking the child process handle. The token is kept alive by the Cmd.
func ExecAs(ctx context.Context, isInDomain bool, domain, username, password string, path string, args ...string) (*exec.Cmd, error) {
	logonType := impersonate.LOGON32_LOGON_NEW_CREDENTIALS

	if !isInDomain {
		logonType = impersonate.LOGON32_LOGON_INTERACTIVE
		domain = "."
	}

	t, err := impersonate.LogonUserW(username, domain, password, logonType, impersonate.LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		return nil, err
	}

	wt := token.New(t, token.Primary)

	if err = wt.EnableAllPrivileges(); err != nil {
		wt.Close()
		return nil, err
	}

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		Token:      syscall.Token(wt.Token()),
	}

	if err := cmd.Start(); err != nil {
		wt.Close()
		return nil, err
	}

	// Token must stay alive while the child process runs.
	// Caller is responsible for cmd.Wait(); the token is closed
	// by GC when the Cmd is garbage collected.
	return cmd, nil
}

// CreateProcessWithLogon executes a program under alternate credentials using
// the Win32 CreateProcessWithLogonW API. Equivalent to "RunAs".
func CreateProcessWithLogon(domain, username, password string, wd string, path string, args ...string) error {
	var logonFlags uint32 = LOGON_WITH_PROFILE

	ptrUsername, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}

	ptrDomain, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return err
	}

	ptrPassword, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}

	ptrCD, err := windows.UTF16PtrFromString(wd)
	if err != nil {
		return err
	}

	ptrPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	ptrCmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return err
	}

	creationFlags := uintptr(windows.CREATE_UNICODE_ENVIRONMENT) | uintptr(windows.CREATE_DEFAULT_ERROR_MODE)
	ptrEnv := uintptr(0)

	ptrStartupInfo := &windows.StartupInfo{
		ShowWindow: windows.SW_HIDE,
		Flags:      windows.STARTF_USESHOWWINDOW,
	}

	ptrProcessInfo := &windows.ProcessInformation{}

	ret, _, e1 := api.ProcCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(ptrUsername)),
		uintptr(unsafe.Pointer(ptrDomain)),
		uintptr(unsafe.Pointer(ptrPassword)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(ptrPath)),
		uintptr(unsafe.Pointer(ptrCmdLine)),
		creationFlags,
		ptrEnv,
		uintptr(unsafe.Pointer(ptrCD)),
		uintptr(unsafe.Pointer(ptrStartupInfo)),
		uintptr(unsafe.Pointer(ptrProcessInfo)),
	)

	runtime.KeepAlive(ptrUsername)
	runtime.KeepAlive(ptrDomain)
	runtime.KeepAlive(ptrPassword)
	runtime.KeepAlive(ptrPath)
	runtime.KeepAlive(ptrCmdLine)
	runtime.KeepAlive(ptrStartupInfo)
	runtime.KeepAlive(ptrCD)
	runtime.KeepAlive(ptrStartupInfo)
	runtime.KeepAlive(ptrProcessInfo)

	if int(ret) == 0 {
		return os.NewSyscallError("CreateProcessWithLogonW", e1)
	}

	defer windows.CloseHandle(windows.Handle(ptrProcessInfo.Process))
	defer windows.CloseHandle(windows.Handle(ptrProcessInfo.Thread))

	return nil
}

// ShellExecuteRunAs executes a program elevated via ShellExecuteW with the
// "runas" verb. Prompts a UAC dialog if the process is not already elevated.
func ShellExecuteRunAs(path, wd string, args ...string) error {
	verb := "runas"

	ptrVerb, err := windows.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}

	ptrExe, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	ptrWd, err := windows.UTF16PtrFromString(wd)
	if err != nil {
		return err
	}

	ptrArgs, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return err
	}

	showWnd := int32(windows.SW_HIDE)

	return windows.ShellExecute(0, ptrVerb, ptrExe, ptrArgs, ptrWd, showWnd)
}
