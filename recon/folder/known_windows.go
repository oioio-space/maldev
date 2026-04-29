//go:build windows

package folder

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// ErrKnownFolderNotFound is returned by [GetKnown] when
// `windows.KnownFolderPath` reports a non-success HRESULT
// (E_INVALIDARG for an unknown GUID, E_FAIL for a folder that
// isn't redirected on the calling principal).
var ErrKnownFolderNotFound = errors.New("recon/folder: SHGetKnownFolderPath returned non-success HRESULT")

// GetKnown returns the resolved path for a KNOWNFOLDERID GUID. It
// is a thin wrapper around `golang.org/x/sys/windows.KnownFolderPath`
// — Microsoft recommends KNOWNFOLDERID over the legacy CSIDL set
// served by [Get], and `windows.KnownFolderPath` already handles
// the `SHGetKnownFolderPath` HRESULT contract + `CoTaskMemFree`
// of the API-allocated `PWSTR`.
//
// Pass any of the `windows.FOLDERID_*` GUIDs (e.g.
// `windows.FOLDERID_RoamingAppData`) and the bitwise OR of any
// required `windows.KF_FLAG_*` flags (e.g. `KF_FLAG_CREATE` to
// create the directory if missing, `KF_FLAG_DONT_VERIFY` to skip
// the existence check).
//
// On failure the returned error wraps [ErrKnownFolderNotFound]
// for `errors.Is` discrimination, with the original windows-side
// error attached via `%w`.
func GetKnown(rfid *windows.KNOWNFOLDERID, flags uint32) (string, error) {
	path, err := windows.KnownFolderPath(rfid, flags)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKnownFolderNotFound, err)
	}
	return path, nil
}
