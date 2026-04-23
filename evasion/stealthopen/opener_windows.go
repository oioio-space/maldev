//go:build windows

package stealthopen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Stealth is the NTFS-Object-ID-backed Opener. Open() bypasses path-based
// EDR file hooks by going through OpenFileById on a volume-root handle
// instead of CreateFile on the target path.
//
// Preconditions:
//   - The target file must be on an NTFS volume (FAT32 / ReFS / network
//     shares without NTFS do not expose Object IDs).
//   - The target file must already have an Object ID. System32 DLLs
//     typically do; newly dropped files may not. Use EnsureObjectID to
//     create one on demand (requires admin only if SetObjectID path is
//     needed; GetObjectID's FSCTL_CREATE_OR_GET_OBJECT_ID works for
//     non-admin in most cases on files the caller already has handles
//     to).
//   - VolumePath must be the root of the volume the file lives on, e.g.
//     `C:\`. Use VolumeFromPath to derive it.
//
// When any precondition fails the Open call returns a descriptive error
// and callers should fall back to a Standard opener (or surface the
// error to the user).
type Stealth struct {
	VolumePath string
	ObjectID   [16]byte
}

// Open implements Opener by calling OpenByID with the pre-captured
// volume path and Object ID. Path-based file hooks never observe the
// target file path.
func (s *Stealth) Open(path string) (*os.File, error) {
	if s == nil {
		return nil, fmt.Errorf("stealthopen: nil Stealth opener")
	}
	if s.VolumePath == "" {
		return nil, fmt.Errorf("stealthopen: Stealth.VolumePath is empty")
	}
	var zero [16]byte
	if s.ObjectID == zero {
		return nil, fmt.Errorf("stealthopen: Stealth.ObjectID is zero")
	}
	return OpenByID(s.VolumePath, s.ObjectID)
}

// NewStealth captures the current NTFS Object ID of path (creating one
// if the file does not yet have one, via FSCTL_CREATE_OR_GET_OBJECT_ID)
// and pairs it with the derived volume root. The returned Stealth can be
// passed as an Opener; subsequent Open calls bypass path hooks entirely.
//
// The path argument is only used here to derive (volumeRoot, objectID) —
// later Open calls ignore the path they receive. Consumers that want
// per-call paths must build a new Stealth per target (or implement a
// custom Opener).
func NewStealth(path string) (*Stealth, error) {
	vol, err := VolumeFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("stealthopen: derive volume: %w", err)
	}
	id, err := GetObjectID(path)
	if err != nil {
		return nil, fmt.Errorf("stealthopen: obtain ObjectID: %w", err)
	}
	return &Stealth{VolumePath: vol, ObjectID: id}, nil
}

// VolumeFromPath returns the volume-root path (e.g. `C:\`) for a file
// path. Accepts drive-absolute paths (`C:\Windows\...`), UNC paths
// (`\\?\Volume{...}\...`, `\\server\share\...`), and relative paths
// (resolved against the current working directory).
//
// The result is always terminated by a trailing backslash — that is the
// form OpenFileById expects for its hVol argument.
func VolumeFromPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}

	// Win32 namespace prefix (`\\?\` or `\\.\`) — strip before analysis,
	// re-add nothing (the volume root is returned as a conventional path).
	tmp := abs
	switch {
	case strings.HasPrefix(tmp, `\\?\`), strings.HasPrefix(tmp, `\\.\`):
		tmp = tmp[4:]
	}

	// UNC \\server\share\...
	if strings.HasPrefix(tmp, `\\`) {
		parts := strings.SplitN(tmp[2:], `\`, 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("malformed UNC path: %q", path)
		}
		return `\\` + parts[0] + `\` + parts[1] + `\`, nil
	}

	// Drive letter C:\...
	if len(tmp) >= 2 && tmp[1] == ':' {
		return strings.ToUpper(tmp[:1]) + `:\`, nil
	}

	// GetVolumePathName fallback for Volume{GUID} roots that came through
	// the Win32 prefix stripper as `Volume{...}\`.
	buf := make([]uint16, windows.MAX_PATH)
	p, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", fmt.Errorf("utf16 convert: %w", err)
	}
	if err := windows.GetVolumePathName(p, &buf[0], uint32(len(buf))); err != nil {
		return "", fmt.Errorf("GetVolumePathName(%q): %w", abs, err)
	}
	vol := windows.UTF16ToString(buf)
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	return vol, nil
}
