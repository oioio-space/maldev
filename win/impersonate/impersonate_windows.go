//go:build windows

// Package impersonate provides Windows thread impersonation utilities.
package impersonate

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/token"
)

// LogonType represents the type of logon operation.
type LogonType uint32

const (
	LOGON32_LOGON_INTERACTIVE LogonType = 2
	LOGON32_LOGON_NETWORK     LogonType = 3
	LOGON32_LOGON_BATCH       LogonType = 4
)

// LogonProvider specifies the logon provider.
type LogonProvider uint32

const (
	LOGON32_PROVIDER_DEFAULT LogonProvider = 0
)

// LogonUserW wraps the advapi32 LogonUserW syscall and returns the resulting
// Windows token.
func LogonUserW(username, domain, password string, logonType LogonType, logonProvider LogonProvider) (windows.Token, error) {
	u := windows.StringToUTF16Ptr(username)
	p := windows.StringToUTF16Ptr(password)
	d := windows.StringToUTF16Ptr(domain)

	handle := uintptr(0)

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

// ImpersonateLoggedOnUser wraps the advapi32 ImpersonateLoggedOnUser syscall.
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

// ImpersonateThread runs callbackFunc on a locked OS thread under the
// credentials of the provided user. The thread reverts to self after
// callbackFunc returns.
func ImpersonateThread(isInDomain bool, domain, username, password string, callbackFunc func() error) error {
	group := new(errgroup.Group)
	group.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		logonType := LOGON32_LOGON_INTERACTIVE
		if !isInDomain {
			logonType = LOGON32_LOGON_NETWORK
		}

		t, err := LogonUserW(username, domain, password, logonType, LOGON32_PROVIDER_DEFAULT)
		if err != nil {
			return err
		}
		defer t.Close()

		wt := token.NewToken(t, token.TokenImpersonation)
		defer wt.Close()

		if err = wt.EnableAllPrivileges(); err != nil {
			return err
		}

		if err = ImpersonateLoggedOnUser(wt.Token()); err != nil {
			return err
		}
		defer windows.RevertToSelf()

		return callbackFunc()
	})

	return group.Wait()
}
