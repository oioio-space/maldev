//go:build windows

package session

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// SessionState mirrors WTS_CONNECTSTATE_CLASS (wtsapi32.h).
type SessionState uint32

const (
	StateActive       SessionState = 0 // user logged in and active on the console
	StateConnected    SessionState = 1 // connected but not yet logged in
	StateConnectQuery SessionState = 2
	StateShadow       SessionState = 3
	StateDisconnected SessionState = 4 // user logged in but session detached (RDP disconnect, lock)
	StateIdle         SessionState = 5
	StateListen       SessionState = 6 // listener (RDP-Tcp, services pool)
	StateReset        SessionState = 7
	StateDown         SessionState = 8
	StateInit         SessionState = 9
)

// String returns the MSDN-style name for the state.
func (s SessionState) String() string {
	switch s {
	case StateActive:
		return "Active"
	case StateConnected:
		return "Connected"
	case StateConnectQuery:
		return "ConnectQuery"
	case StateShadow:
		return "Shadow"
	case StateDisconnected:
		return "Disconnected"
	case StateIdle:
		return "Idle"
	case StateListen:
		return "Listen"
	case StateReset:
		return "Reset"
	case StateDown:
		return "Down"
	case StateInit:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(s))
	}
}

// Info describes a Terminal Services / Remote Desktop session on the
// current server.
type Info struct {
	ID     uint32       // session ID (0 = services, 1 = console, 2+ = RDP / fast-user-switch)
	Name   string       // WinStation name ("Console", "Services", "RDP-Tcp#0", …)
	State  SessionState // connection state
	User   string       // logged-on user, empty for listener / services sessions
	Domain string       // user's domain, empty when User is empty
}

// WTS_CURRENT_SERVER_HANDLE selects the current host in WTSEnumerateSessions.
// (golang.org/x/sys/windows does not export this constant.)
const wtsCurrentServerHandle = 0

// WTS_INFO_CLASS values used by WTSQuerySessionInformation.
const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// List enumerates every Terminal Services session on the current server
// via WTSEnumerateSessions and enriches each with user + domain via
// WTSQuerySessionInformationW. No elevation required.
func List() ([]Info, error) {
	var raw uintptr
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServerHandle, 0, 1,
		(**windows.WTS_SESSION_INFO)(unsafe.Pointer(&raw)), &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(raw)

	size := unsafe.Sizeof(windows.WTS_SESSION_INFO{})
	out := make([]Info, 0, count)
	for i := uint32(0); i < count; i++ {
		entry := (*windows.WTS_SESSION_INFO)(unsafe.Pointer(raw + (size * uintptr(i))))
		out = append(out, Info{
			ID:     entry.SessionID,
			Name:   windows.UTF16PtrToString(entry.WindowStationName),
			State:  SessionState(entry.State),
			User:   querySessionString(entry.SessionID, wtsUserName),
			Domain: querySessionString(entry.SessionID, wtsDomainName),
		})
	}
	return out, nil
}

// Active returns only sessions in Active state that carry a logged-in user.
// Excludes the Services session (ID 0) and listener sessions.
func Active() ([]Info, error) {
	sessions, err := List()
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(sessions))
	for _, s := range sessions {
		if s.State == StateActive && s.User != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// querySessionString calls WTSQuerySessionInformationW for the given
// InfoClass and returns the resulting UTF-16 string. Empty string on
// failure — callers treat missing data as absence rather than error.
func querySessionString(sessionID uint32, infoClass int) string {
	var buf *uint16
	var length uint32
	r, _, _ := api.ProcWTSQuerySessionInformationW.Call(
		wtsCurrentServerHandle,
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&length)),
	)
	if r == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}
