//go:build windows

package bof

import (
	"encoding/binary"
	"sync"
	"syscall"
	"unsafe"
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

// resolveBeaconImport returns the Go-side callback address for the given
// COFF external symbol name, e.g. "__imp_BeaconPrintf". Returns ok=false
// when the symbol is not part of the implemented Beacon API surface.
func resolveBeaconImport(name string) (uintptr, bool) {
	beaconCBsOnce.Do(initBeaconCallbacks)
	addr, ok := beaconCBs[name]
	return addr, ok
}

func initBeaconCallbacks() {
	beaconCBs = map[string]uintptr{
		"__imp_BeaconPrintf":      syscall.NewCallback(beaconPrintfImpl),
		"__imp_BeaconOutput":      syscall.NewCallback(beaconOutputImpl),
		"__imp_BeaconDataParse":   syscall.NewCallback(beaconDataParseImpl),
		"__imp_BeaconDataInt":     syscall.NewCallback(beaconDataIntImpl),
		"__imp_BeaconDataShort":   syscall.NewCallback(beaconDataShortImpl),
		"__imp_BeaconDataLength":  syscall.NewCallback(beaconDataLengthImpl),
		"__imp_BeaconDataExtract": syscall.NewCallback(beaconDataExtractImpl),
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
type dataParser struct {
	original uintptr
	buffer   uintptr
	length   int32
	_        [4]byte // padding to align with the C struct on x64
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

// cStringFromPtr reads a NUL-terminated C string from ptr, capping at max
// bytes to avoid runaway reads on a malformed pointer.
func cStringFromPtr(ptr uintptr, max int) string {
	if ptr == 0 {
		return ""
	}
	for n := 0; n < max; n++ {
		if *(*byte)(unsafe.Pointer(ptr + uintptr(n))) == 0 {
			return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n))
		}
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), max))
}
