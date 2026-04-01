//go:build windows

// Package session provides utilities for executing processes and impersonating
// threads in other user sessions.
package session

import (
	"runtime"
	"unsafe"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/impersonate"
	"github.com/oioio-space/maldev/win/token"
)

// CreateProcessOnActiveSessions creates a process in the context of the
// specified user token.
func CreateProcessOnActiveSessions(userToken *token.Token, executable string, args []string) error {
	executable16, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}

	args16, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return err
	}

	userDetails, err := userToken.UserDetails()
	if err != nil {
		return err
	}

	workingDirectory16, err := windows.UTF16PtrFromString(userDetails.UserProfileDir)
	if err != nil {
		return err
	}

	var environmentBlock *uint16
	ret, _, e1 := api.Userenv.NewProc("CreateEnvironmentBlock").Call(
		uintptr(unsafe.Pointer(&environmentBlock)),
		uintptr(userToken.Token()),
		0,
	)
	if ret == 0 {
		return e1
	}

	attributList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}

	si := &windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		ProcThreadAttributeList: attributList.List(),
	}

	handles := []windows.Handle{0}
	attributList.Update(
		windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	)

	pi := new(windows.ProcessInformation)

	err = windows.CreateProcessAsUser(
		userToken.Token(),
		executable16,
		args16,
		nil,
		nil,
		true,
		windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		environmentBlock,
		workingDirectory16,
		&si.StartupInfo,
		pi,
	)
	windows.CloseHandle(pi.Thread)
	attributList.Delete()
	api.Userenv.NewProc("DestroyEnvironmentBlock").Call(uintptr(unsafe.Pointer(environmentBlock)))

	return err
}

// ImpersonateThreadOnActiveSession runs callbackFunc on a locked OS thread
// under the credentials of the provided user token.
func ImpersonateThreadOnActiveSession(userToken *token.Token, callbackFunc func() error) error {
	group := new(errgroup.Group)
	group.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err := impersonate.ImpersonateLoggedOnUser(userToken.Token())
		if err != nil {
			return err
		}
		defer windows.RevertToSelf()

		return callbackFunc()
	})

	return group.Wait()
}
