//go:build windows

package folder

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// KNOWNFOLDERID GUIDs covering the most-used Shell folders. Microsoft
// recommends [SHGetKnownFolderPath] over the legacy
// [SHGetSpecialFolderPathW] (CSIDL) — KNOWNFOLDERID is extensible
// (3rd-party shell extensions register their own GUIDs) and the
// returned path is owned by the API (frees through CoTaskMemFree)
// rather than capped at MAX_PATH.
//
// [SHGetKnownFolderPath]: https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
// [SHGetSpecialFolderPathW]: https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpathw
var (
	FOLDERID_Profile        = mustGUID("{5E6C858F-0E22-4760-9AFE-EA3317B67173}")
	FOLDERID_Desktop        = mustGUID("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")
	FOLDERID_Documents      = mustGUID("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}")
	FOLDERID_Downloads      = mustGUID("{374DE290-123F-4565-9164-39C4925E467B}")
	FOLDERID_LocalAppData   = mustGUID("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}")
	FOLDERID_RoamingAppData = mustGUID("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}")
	FOLDERID_Programs       = mustGUID("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}")
	FOLDERID_Startup        = mustGUID("{B97D20BB-F46A-4C97-BA10-5E3608430854}")
	FOLDERID_System         = mustGUID("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}")
	FOLDERID_Windows        = mustGUID("{F38BF404-1D43-42F2-9305-67DE0B28FC23}")
	FOLDERID_ProgramFiles   = mustGUID("{905E63B6-C1BF-494E-B29C-65B732D3D21A}")
	FOLDERID_ProgramFilesX86 = mustGUID("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}")
	FOLDERID_PublicDesktop  = mustGUID("{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}")
	FOLDERID_CommonStartup  = mustGUID("{82A5EA35-D9CC-47CA-9628-E40C2C1F3D8B}")
)

// KnownFolderFlag mirrors the Windows KNOWN_FOLDER_FLAG enumeration.
// Pass 0 for "default behaviour".
type KnownFolderFlag uint32

const (
	KFF_DEFAULT_PATH       KnownFolderFlag = 0x00000400
	KFF_NOT_PARENT_RELATIVE KnownFolderFlag = 0x00000200
	KFF_DONT_VERIFY        KnownFolderFlag = 0x00004000
	KFF_CREATE             KnownFolderFlag = 0x00008000
	KFF_NO_ALIAS           KnownFolderFlag = 0x00001000
	KFF_INIT               KnownFolderFlag = 0x00000800
)

// ErrKnownFolderNotFound is returned when SHGetKnownFolderPath returns
// E_INVALIDARG (unknown GUID) or E_FAIL (folder not redirected).
var ErrKnownFolderNotFound = errors.New("recon/folder: SHGetKnownFolderPath returned non-success HRESULT")

// GetKnown returns the resolved path for a KNOWNFOLDERID GUID.
//
// Mirrors `SHGetKnownFolderPath(rfid, dwFlags, hToken=NULL, &pszPath)`
// semantics: the API returns an `HRESULT` and writes a `*PWSTR` that
// the caller MUST free via `CoTaskMemFree`. This wrapper handles the
// free internally.
//
// Pass `KFF_CREATE` to force directory creation when missing (mirrors
// the `createIfNotExist` knob on the legacy `Get`). Pass 0 for the
// default "look up only" behaviour.
func GetKnown(rfid windows.GUID, flags KnownFolderFlag) (string, error) {
	var pszPath *uint16
	hr, _, _ := api.ProcSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&rfid)),
		uintptr(flags),
		0, // hToken == NULL → current user
		uintptr(unsafe.Pointer(&pszPath)),
	)
	if pszPath != nil {
		defer api.ProcCoTaskMemFree.Call(uintptr(unsafe.Pointer(pszPath)))
	}
	if hr != 0 {
		return "", fmt.Errorf("%w: hresult=0x%x", ErrKnownFolderNotFound, uint32(hr))
	}
	return windows.UTF16PtrToString(pszPath), nil
}

// mustGUID parses the standard `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`
// form. Used at init time on hard-coded constants — panics on bad
// input because the constant is wrong if it ever fails.
func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(fmt.Sprintf("recon/folder: invalid hard-coded GUID %q: %v", s, err))
	}
	return g
}
