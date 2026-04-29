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

// Options tunes [CreateProcessOnActiveSessionsWith].
type Options struct {
	// Desktop is the destination "winstation\desktop" name passed via
	// STARTUPINFOW.lpDesktop. Empty (default) inherits the parent
	// process's station and desktop — typically "Winsta0\Default" for
	// an interactive user session, which is what every UI element on
	// the user's screen lives on. Set this when targeting an alternate
	// station (e.g. "Service-0x0-3e7$\Default" for a SYSTEM service
	// session) or a hidden desktop you created via
	// CreateDesktop / CreateWindowStation upstream.
	Desktop string
}

// CreateProcessOnActiveSessions creates a process in the context of the
// specified user token. Equivalent to
// [CreateProcessOnActiveSessionsWith] with a zero [Options] (default
// desktop inherited from the caller).
func CreateProcessOnActiveSessions(userToken *token.Token, executable string, args []string) error {
	return CreateProcessOnActiveSessionsWith(userToken, executable, args, Options{})
}

// CreateProcessOnActiveSessionsWith is the [Options]-aware variant of
// [CreateProcessOnActiveSessions]. Use it to override the destination
// window station / desktop via [Options.Desktop]; nil-valued fields
// behave exactly like the legacy entry point.
func CreateProcessOnActiveSessionsWith(userToken *token.Token, executable string, args []string, opts Options) error {
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
	ret, _, e1 := api.ProcCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&environmentBlock)),
		uintptr(userToken.Token()),
		0,
	)
	if ret == 0 {
		return e1
	}

	si := &windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})),
	}
	if opts.Desktop != "" {
		desktop16, err := windows.UTF16PtrFromString(opts.Desktop)
		if err != nil {
			api.ProcDestroyEnvironmentBlock.Call(uintptr(unsafe.Pointer(environmentBlock)))
			return err
		}
		si.Desktop = desktop16
	}

	pi := new(windows.ProcessInformation)

	err = windows.CreateProcessAsUser(
		userToken.Token(),
		executable16,
		args16,
		nil,
		nil,
		false,
		windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT,
		environmentBlock,
		workingDirectory16,
		si,
		pi,
	)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	api.ProcDestroyEnvironmentBlock.Call(uintptr(unsafe.Pointer(environmentBlock)))

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
