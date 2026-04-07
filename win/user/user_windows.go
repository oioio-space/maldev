//go:build windows

package user

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// Sentinel errors for caller-side matching.
var (
	ErrUserExists    = errors.New("user already exists")
	ErrUserNotFound  = errors.New("user not found")
	ErrAccessDenied  = errors.New("access denied")
	ErrGroupNotFound = errors.New("group not found")
)

// NERR and system error codes returned by NetAPI32.
const (
	nerrSuccess       = 0
	nerrUserNotFound  = 2221
	nerrGroupNotFound = 2220
	nerrUserExists    = 2224
	errorAccessDenied = 5
)

// User account flag constants.
const (
	ufScript           = 0x0001
	ufDontExpirePasswd = 0x10000
	userPrivUser       = 1
)

// Lazy proc references from the shared Netapi32 DLL handle.
var (
	procNetUserAdd              = api.Netapi32.NewProc("NetUserAdd")
	procNetUserDel              = api.Netapi32.NewProc("NetUserDel")
	procNetUserSetInfo          = api.Netapi32.NewProc("NetUserSetInfo")
	procNetUserGetInfo          = api.Netapi32.NewProc("NetUserGetInfo")
	procNetUserEnum             = api.Netapi32.NewProc("NetUserEnum")
	procNetLocalGroupAddMembers = api.Netapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = api.Netapi32.NewProc("NetLocalGroupDelMembers")
	procNetAPIBufferFree        = api.Netapi32.NewProc("NetApiBufferFree")
)

// userInfo1 maps to the Windows USER_INFO_1 structure used by NetUserAdd level 1.
type userInfo1 struct {
	Name       *uint16
	Password   *uint16
	PasswordAge uint32
	Priv       uint32
	HomeDir    *uint16
	Comment    *uint16
	Flags      uint32
	ScriptPath *uint16
}

// userInfo1003 maps to USER_INFO_1003, used by NetUserSetInfo level 1003
// to change only the password field.
type userInfo1003 struct {
	Password *uint16
}

// userInfo0 maps to USER_INFO_0, used by NetUserEnum level 0.
type userInfo0 struct {
	Name *uint16
}

// localGroupMembersInfo3 maps to LOCALGROUP_MEMBERS_INFO_3 (level 3),
// which identifies a member by domain-qualified name.
type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

// Info represents a local Windows user account.
type Info struct {
	Name     string
	FullName string
	Comment  string
	Flags    uint32
}

// Add creates a new local user account with the given name and password.
func Add(name, password string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encoding name: %w", err)
	}
	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("encoding password: %w", err)
	}

	info := userInfo1{
		Name:     namePtr,
		Password: passPtr,
		Priv:     userPrivUser,
		Flags:    ufScript | ufDontExpirePasswd,
	}

	var parmErr uint32
	ret, _, _ := procNetUserAdd.Call(
		0, // servername nil = local
		1, // level
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	return mapNetError("add user", ret)
}

// Delete removes a local user account.
func Delete(name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encoding name: %w", err)
	}

	ret, _, _ := procNetUserDel.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
	)
	return mapNetError("delete user", ret)
}

// SetPassword changes a user's password.
func SetPassword(name, password string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encoding name: %w", err)
	}
	passPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("encoding password: %w", err)
	}

	info := userInfo1003{Password: passPtr}

	ret, _, _ := procNetUserSetInfo.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		1003,
		uintptr(unsafe.Pointer(&info)),
		0, // parm_err
	)
	return mapNetError("set password", ret)
}

// AddToGroup adds a user to a local group.
func AddToGroup(name, group string) error {
	return modifyGroupMembership(name, group, procNetLocalGroupAddMembers)
}

// RemoveFromGroup removes a user from a local group.
func RemoveFromGroup(name, group string) error {
	return modifyGroupMembership(name, group, procNetLocalGroupDelMembers)
}

// adminGroupName resolves the locale-independent Administrators group name
// from the well-known SID S-1-5-32-544. On non-English Windows the group
// has a localized name (e.g., "Administratoren" in German).
func adminGroupName() (string, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("resolve admin SID: %w", err)
	}
	account, _, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("lookup admin group: %w", err)
	}
	return account, nil
}

// SetAdmin adds a user to the built-in Administrators group.
// Uses SID-based lookup for locale independence.
func SetAdmin(name string) error {
	group, err := adminGroupName()
	if err != nil {
		return err
	}
	return AddToGroup(name, group)
}

// RevokeAdmin removes a user from the built-in Administrators group.
// Uses SID-based lookup for locale independence.
func RevokeAdmin(name string) error {
	group, err := adminGroupName()
	if err != nil {
		return err
	}
	return RemoveFromGroup(name, group)
}

// Exists checks whether a local user account exists.
func Exists(name string) bool {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}

	var buf uintptr
	ret, _, _ := procNetUserGetInfo.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		0, // level 0 = USER_INFO_0, minimal data
		uintptr(unsafe.Pointer(&buf)),
	)
	if buf != 0 {
		procNetAPIBufferFree.Call(buf) //nolint:errcheck
	}
	return ret == nerrSuccess
}

// List returns all local user accounts.
func List() ([]Info, error) {
	var (
		buf          unsafe.Pointer
		entriesRead  uint32
		totalEntries uint32
		resumeHandle uint32
		users        []Info
	)

	for {
		ret, _, _ := procNetUserEnum.Call(
			0, // local machine
			0, // level 0
			0, // filter (0 = all)
			uintptr(unsafe.Pointer(&buf)),
			0xFFFFFFFF, // prefmaxlen = MAX_PREFERRED_LENGTH
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)

		if buf != nil {
			entries := unsafe.Slice((*userInfo0)(buf), entriesRead)
			for _, e := range entries {
				users = append(users, Info{
					Name: windows.UTF16PtrToString(e.Name),
				})
			}
			procNetAPIBufferFree.Call(uintptr(buf)) //nolint:errcheck
			buf = nil
		}

		// 234 = ERROR_MORE_DATA
		if ret == 234 {
			continue
		}
		if ret != nerrSuccess {
			return nil, mapNetError("enumerate users", ret)
		}
		break
	}
	return users, nil
}

// IsAdmin checks whether the current process token is a member of the
// built-in Administrators group. This uses a proper SID membership check
// rather than relying on token elevation, which handles UAC split tokens.
func IsAdmin() bool {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	token := windows.GetCurrentProcessToken()
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// modifyGroupMembership adds or removes a user from a local group using
// the supplied NetLocalGroup proc (add or delete).
func modifyGroupMembership(name, group string, proc *windows.LazyProc) error {
	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return fmt.Errorf("encoding group: %w", err)
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encoding name: %w", err)
	}

	info := localGroupMembersInfo3{DomainAndName: namePtr}

	ret, _, _ := proc.Call(
		0,
		uintptr(unsafe.Pointer(groupPtr)),
		3, // level 3 = LOCALGROUP_MEMBERS_INFO_3
		uintptr(unsafe.Pointer(&info)),
		1, // totalentries
	)
	return mapNetError("modify group membership", ret)
}

// mapNetError translates a NetAPI return code into a typed Go error.
// The operation string describes the action without including OPSEC-sensitive
// details like usernames or group names.
func mapNetError(op string, ret uintptr) error {
	switch ret {
	case nerrSuccess:
		return nil
	case nerrUserExists:
		return fmt.Errorf("%s: %w", op, ErrUserExists)
	case nerrUserNotFound:
		return fmt.Errorf("%s: %w", op, ErrUserNotFound)
	case nerrGroupNotFound:
		return fmt.Errorf("%s: %w", op, ErrGroupNotFound)
	case errorAccessDenied:
		return fmt.Errorf("%s: %w", op, ErrAccessDenied)
	default:
		return fmt.Errorf("%s: net error %d", op, ret)
	}
}
