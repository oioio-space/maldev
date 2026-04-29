//go:build windows

package lnk

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/win/api"
	"github.com/oioio-space/maldev/win/com"
	"golang.org/x/sys/windows"
)

// Zero-disk LNK serialisation: IShellLinkW + IPersistStream::Save onto a
// CreateStreamOnHGlobal IStream. The bytes are pulled out of the HGLOBAL
// before the stream is released — no filesystem call at any point.
//
// References: MS-SHLLINK; ObjIdl.h IShellLinkW / IPersistStream;
// ole32!CreateStreamOnHGlobal.

var (
	clsidShellLink   = ole.NewGUID("{00021401-0000-0000-C000-000000000046}")
	iidShellLinkW    = ole.NewGUID("{000214F9-0000-0000-C000-000000000046}")
	iidPersistStream = ole.NewGUID("{00000109-0000-0000-C000-000000000046}")

	procCreateStreamOnHGlobal = api.Ole32.NewProc("CreateStreamOnHGlobal")
	procGetHGlobalFromStream  = api.Ole32.NewProc("GetHGlobalFromStream")

	procGlobalSize   = api.Kernel32.NewProc("GlobalSize")
	procGlobalLock   = api.Kernel32.NewProc("GlobalLock")
	procGlobalUnlock = api.Kernel32.NewProc("GlobalUnlock")
)

const (
	idxShellLinkSetDescription = 7
	idxShellLinkSetWorkingDir  = 9
	idxShellLinkSetArguments   = 11
	idxShellLinkSetHotkey      = 13
	idxShellLinkSetShowCmd     = 15
	idxShellLinkSetIconLoc     = 17
	idxShellLinkSetPath        = 20

	idxPersistStreamSave = 6
)

// HOTKEYF_* mask bits packed in the high byte of IShellLinkW::SetHotkey's
// WORD argument.
const (
	hotkeyfShift   = 0x01
	hotkeyfControl = 0x02
	hotkeyfAlt     = 0x04
	hotkeyfExt     = 0x08
)

const ptrSize = unsafe.Sizeof(uintptr(0))

// vtblFn looks up the function pointer at vtable index `index` for the
// COM object whose `this` pointer is p.
func vtblFn(p uintptr, index int) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(p))
	return *(*uintptr)(unsafe.Pointer(vtbl + uintptr(index)*ptrSize))
}

// callVtbl invokes vtable slot `index` on the COM object `this` with `args`
// (excluding `this` itself, which is prepended). Returns the HRESULT.
func callVtbl(this uintptr, index int, args ...uintptr) uintptr {
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, this)
	all = append(all, args...)
	hr, _, _ := syscall.SyscallN(vtblFn(this, index), all...)
	return hr
}

// parseHotkey converts a WSH-style hotkey string ("Ctrl+Alt+T", "Shift+F1",
// "Alt+1") into the packed WORD form expected by IShellLinkW::SetHotkey:
// low byte = VK code, high byte = HOTKEYF_* mask. Returns ok=false if the
// string is empty or unparseable so the caller can skip the call.
func parseHotkey(s string) (uint16, bool) {
	if s == "" {
		return 0, false
	}
	var mods, vk uint16
	parts := strings.Split(s, "+")
	for _, p := range parts {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "ctrl", "control":
			mods |= hotkeyfControl
		case "alt":
			mods |= hotkeyfAlt
		case "shift":
			mods |= hotkeyfShift
		case "ext":
			mods |= hotkeyfExt
		default:
			key := strings.ToUpper(strings.TrimSpace(p))
			switch {
			case len(key) == 1 && key[0] >= 'A' && key[0] <= 'Z':
				vk = uint16(key[0]) // VK_A (0x41) ... VK_Z (0x5A)
			case len(key) == 1 && key[0] >= '0' && key[0] <= '9':
				vk = uint16(key[0]) // VK_0 (0x30) ... VK_9 (0x39)
			case len(key) >= 2 && key[0] == 'F':
				n := 0
				for i := 1; i < len(key); i++ {
					c := key[i]
					if c < '0' || c > '9' {
						return 0, false
					}
					n = n*10 + int(c-'0')
				}
				if n < 1 || n > 24 {
					return 0, false
				}
				vk = 0x70 + uint16(n-1) // VK_F1 = 0x70
			default:
				return 0, false
			}
		}
	}
	if vk == 0 {
		return 0, false
	}
	return mods<<8 | vk, true
}

// splitIconLocation parses the WSH-style "path,index" string maintained
// by [Shortcut.SetIconLocation] for compatibility with the IDispatch
// path. A missing or non-numeric tail defaults the index to 0.
func splitIconLocation(s string) (string, int) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ',' {
			continue
		}
		n := 0
		for j := i + 1; j < len(s); j++ {
			c := s[j]
			if c < '0' || c > '9' {
				return s, 0
			}
			n = n*10 + int(c-'0')
		}
		return s[:i], n
	}
	return s, 0
}

func configureShellLinkW(sl uintptr, s *Shortcut) error {
	stringSetters := []struct {
		index int
		stage string
		val   string
	}{
		{idxShellLinkSetPath, "SetPath", s.targetPath},
		{idxShellLinkSetArguments, "SetArguments", s.arguments},
		{idxShellLinkSetWorkingDir, "SetWorkingDirectory", s.workingDir},
		{idxShellLinkSetDescription, "SetDescription", s.description},
	}
	for _, e := range stringSetters {
		if e.val == "" {
			continue
		}
		ptr, err := windows.UTF16PtrFromString(e.val)
		if err != nil {
			return fmt.Errorf("lnk: utf16(%s): %w", e.stage, err)
		}
		if err := com.Error(e.stage, callVtbl(sl, e.index, uintptr(unsafe.Pointer(ptr)))); err != nil {
			return err
		}
	}

	if s.iconLocation != "" {
		path, idx := splitIconLocation(s.iconLocation)
		ptr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return fmt.Errorf("lnk: utf16(IconLocation): %w", err)
		}
		if err := com.Error("SetIconLocation",
			callVtbl(sl, idxShellLinkSetIconLoc, uintptr(unsafe.Pointer(ptr)), uintptr(idx))); err != nil {
			return err
		}
	}

	if s.styleSet {
		if err := com.Error("SetShowCmd",
			callVtbl(sl, idxShellLinkSetShowCmd, uintptr(int(s.windowStyle)))); err != nil {
			return err
		}
	}

	if hk, ok := parseHotkey(s.hotkey); ok {
		if err := com.Error("SetHotkey",
			callVtbl(sl, idxShellLinkSetHotkey, uintptr(hk))); err != nil {
			return err
		}
	}
	return nil
}

// asUnknown reinterprets a raw COM pointer as *ole.IUnknown so go-ole's
// AddRef/Release/QueryInterface implementations can be used in lieu of
// hand-rolled vtable syscalls. Safe because every COM object's first
// machine word is its vtable pointer — same shape as ole.IUnknown.
func asUnknown(p uintptr) *ole.IUnknown {
	return (*ole.IUnknown)(unsafe.Pointer(p))
}

// BuildBytes serialises the shortcut to LNK bytes entirely in memory
// via IShellLinkW + IPersistStream::Save into an HGLOBAL-backed
// IStream. No filesystem call is made.
//
// Output is bit-identical to what [Shortcut.Save] writes — IPersistStream
// is the same serialiser the shell invokes when IPersistFile::Save runs.
//
// Use case: embed bytes in a payload, hand to a C2 transport, feed to
// an operator-controlled write primitive (encrypted ADS, in-memory
// mount, custom Opener).
func (s *Shortcut) BuildBytes() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_SPEED_OVER_MEMORY); err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || oleErr.Code() != 0x00000001 {
			return nil, fmt.Errorf("lnk: COM init: %w", err)
		}
	}
	defer ole.CoUninitialize()

	sl, err := ole.CreateInstance(clsidShellLink, iidShellLinkW)
	if err != nil {
		return nil, fmt.Errorf("lnk: create IShellLinkW: %w", err)
	}
	slPtr := uintptr(unsafe.Pointer(sl))
	defer sl.Release()

	if err := configureShellLinkW(slPtr, s); err != nil {
		return nil, err
	}

	// Raw QueryInterface: go-ole's typed wrapper forces *IDispatch.
	var psPtr uintptr
	if err := com.Error("QueryInterface(IPersistStream)",
		callVtbl(slPtr, 0,
			uintptr(unsafe.Pointer(iidPersistStream)),
			uintptr(unsafe.Pointer(&psPtr)))); err != nil {
		return nil, err
	}
	defer asUnknown(psPtr).Release()

	// fDeleteOnRelease=TRUE — the underlying HGLOBAL is freed when the
	// stream is released. Bytes must be copied out before that point.
	var streamPtr uintptr
	hr, _, _ := procCreateStreamOnHGlobal.Call(0, 1, uintptr(unsafe.Pointer(&streamPtr)))
	if err := com.Error("CreateStreamOnHGlobal", hr); err != nil {
		return nil, err
	}
	defer asUnknown(streamPtr).Release()

	if err := com.Error("IPersistStream::Save",
		callVtbl(psPtr, idxPersistStreamSave, streamPtr, 1)); err != nil {
		return nil, err
	}

	return readHGlobalFromStream(streamPtr)
}

func readHGlobalFromStream(streamPtr uintptr) ([]byte, error) {
	var hglobal uintptr
	hr, _, _ := procGetHGlobalFromStream.Call(streamPtr, uintptr(unsafe.Pointer(&hglobal)))
	if err := com.Error("GetHGlobalFromStream", hr); err != nil {
		return nil, err
	}

	size, _, _ := procGlobalSize.Call(hglobal)
	if size == 0 {
		return nil, fmt.Errorf("lnk: IPersistStream produced empty HGLOBAL")
	}

	ptr, _, callErr := procGlobalLock.Call(hglobal)
	if ptr == 0 {
		return nil, fmt.Errorf("lnk: GlobalLock: %w", callErr)
	}
	defer procGlobalUnlock.Call(hglobal)

	buf := make([]byte, size)
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size))
	return buf, nil
}

// WriteTo writes the LNK bytes to w. Pair with any io.Writer the
// operator controls. The serialisation path is identical to
// [Shortcut.BuildBytes].
func (s *Shortcut) WriteTo(w io.Writer) (int64, error) {
	b, err := s.BuildBytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

// WriteVia lands the LNK bytes on disk through the operator-supplied
// [stealthopen.Creator]. nil falls back to a [stealthopen.StandardCreator]
// (plain os.Create), which makes WriteVia a drop-in replacement for
// [Shortcut.Save] that produces an identical file.
//
// Use a non-nil Creator to route the write through transactional NTFS,
// an encrypted-stream wrapper, an alternate data stream, or any other
// operator-controlled write primitive — same composition story as
// [stealthopen.Opener] for read paths. Bytes are produced by
// [Shortcut.BuildBytes] (zero intermediate disk artefact); only the
// final landing is on the operator's terms.
func (s *Shortcut) WriteVia(creator stealthopen.Creator, path string) error {
	b, err := s.BuildBytes()
	if err != nil {
		return err
	}
	wc, err := stealthopen.UseCreator(creator).Create(path)
	if err != nil {
		return fmt.Errorf("lnk: WriteVia create %q: %w", path, err)
	}
	defer wc.Close()
	if _, err := wc.Write(b); err != nil {
		return fmt.Errorf("lnk: WriteVia write %q: %w", path, err)
	}
	return nil
}
