//go:build windows

package bof

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCurrentBOF runs fn with currentBOF set to a freshly-built BOF that has
// an output buffer. The bofMu lock and currentBOF restoration are handled
// here so individual stub tests stay focused on the assertion.
func withCurrentBOF(t *testing.T, fn func(b *BOF)) {
	t.Helper()
	bofMu.Lock()
	defer bofMu.Unlock()
	b := &BOF{output: newBeaconOutput()}
	currentBOF = b
	defer func() { currentBOF = nil }()
	fn(b)
}

func TestResolveBeaconImport_KnownNames(t *testing.T) {
	want := []string{
		"__imp_BeaconPrintf",
		"__imp_BeaconOutput",
		"__imp_BeaconDataParse",
		"__imp_BeaconDataInt",
		"__imp_BeaconDataShort",
		"__imp_BeaconDataLength",
		"__imp_BeaconDataExtract",
	}
	for _, name := range want {
		addr, ok := resolveBeaconImport(name)
		require.True(t, ok, "%s must resolve", name)
		assert.NotZero(t, addr, "%s callback address must be non-zero", name)
	}
}

func TestResolveBeaconImport_Unknown(t *testing.T) {
	addr, ok := resolveBeaconImport("__imp_TotallyMadeUpFunction")
	assert.False(t, ok)
	assert.Zero(t, addr)
}

// TestResolveBeaconImport_DollarImport confirms that CS-format dynamic-link
// imports (__imp_<DLL>$<Func>) resolve via the PEB walk + ROR13 path. We pick
// kernel32!LoadLibraryA because it is always loaded and never hooked at the
// export-table level (only the prologue).
func TestResolveBeaconImport_DollarImport(t *testing.T) {
	addr, ok := resolveBeaconImport("__imp_KERNEL32$LoadLibraryA")
	require.True(t, ok, "KERNEL32$LoadLibraryA must resolve via api.ResolveByHash")
	assert.NotZero(t, addr)
}

func TestParseDollarImport(t *testing.T) {
	cases := []struct {
		in      string
		dll, fn string
		ok      bool
	}{
		{"__imp_KERNEL32$LoadLibraryA", "KERNEL32.DLL", "LoadLibraryA", true},
		{"__imp_kernel32$GetModuleHandleA", "KERNEL32.DLL", "GetModuleHandleA", true},
		{"__imp_USER32.DLL$MessageBoxW", "USER32.DLL", "MessageBoxW", true},
		{"__imp_BeaconPrintf", "", "", false},      // no $ separator
		{"BeaconPrintf", "", "", false},            // no __imp_ prefix
		{"__imp_$LoadLibraryA", "", "", false},     // empty DLL
		{"__imp_KERNEL32$", "", "", false},         // empty function
		{"__imp_KERNEL32$$LoadLibraryA", "KERNEL32.DLL", "$LoadLibraryA", true}, // first $ wins
	}
	for _, c := range cases {
		dll, fn, ok := parseDollarImport(c.in)
		assert.Equal(t, c.ok, ok, "in=%q ok", c.in)
		if c.ok {
			assert.Equal(t, c.dll, dll, "in=%q dll", c.in)
			assert.Equal(t, c.fn, fn, "in=%q fn", c.in)
		}
	}
}

func TestBeaconPrintfImpl_CapturesOutput(t *testing.T) {
	withCurrentBOF(t, func(b *BOF) {
		// NUL-terminated C string in a stable backing array.
		msg := []byte("hello bof\x00")
		ptr := uintptr(unsafe.Pointer(&msg[0]))
		ret := beaconPrintfImpl(0, ptr)
		assert.Zero(t, ret)
		assert.Equal(t, "hello bof", b.output.String())
	})
}

func TestBeaconPrintfImpl_NoCurrentBOF(t *testing.T) {
	// currentBOF is nil outside a withCurrentBOF block — the stub must
	// not panic on a missing receiver.
	bofMu.Lock()
	defer bofMu.Unlock()
	currentBOF = nil
	msg := []byte("ignored\x00")
	ret := beaconPrintfImpl(0, uintptr(unsafe.Pointer(&msg[0])))
	assert.Zero(t, ret)
}

func TestBeaconOutputImpl_CopiesBytes(t *testing.T) {
	withCurrentBOF(t, func(b *BOF) {
		raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		ret := beaconOutputImpl(0, uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)))
		assert.Zero(t, ret)
		assert.Equal(t, raw, b.output.Bytes())
	})
}

func TestBeaconOutputImpl_ZeroLength(t *testing.T) {
	withCurrentBOF(t, func(b *BOF) {
		raw := []byte{0xAA}
		ret := beaconOutputImpl(0, uintptr(unsafe.Pointer(&raw[0])), 0)
		assert.Zero(t, ret)
		assert.Empty(t, b.output.Bytes())
	})
}

// TestBeaconDataParse_RoundTrip packs an arg buffer in the CS-compatible
// format (uint32 total-length header + length-prefixed values) and walks
// it through ParseData / DataInt / DataShort / DataLength / DataExtract.
func TestBeaconDataParse_RoundTrip(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		// Build payload: int(0x12345678) + short(0x9ABC) + bytes("xyz").
		var payload []byte
		payload = binary.LittleEndian.AppendUint32(payload, 0x12345678)
		payload = binary.LittleEndian.AppendUint16(payload, 0x9ABC)
		payload = binary.LittleEndian.AppendUint32(payload, 3) // length prefix for the string
		payload = append(payload, 'x', 'y', 'z')

		// Frame: uint32 total-length header + payload.
		buf := make([]byte, 4+len(payload))
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
		copy(buf[4:], payload)

		var p dataParser
		beaconDataParseImpl(uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		assert.Equal(t, int32(len(payload)), p.length, "parser length matches header value")

		// Read int — should consume 4 bytes and return 0x12345678.
		v := beaconDataIntImpl(uintptr(unsafe.Pointer(&p)))
		assert.Equal(t, uintptr(0x12345678), v)

		// Read short — should consume 2 bytes and return 0x9ABC.
		s := beaconDataShortImpl(uintptr(unsafe.Pointer(&p)))
		assert.Equal(t, uintptr(0x9ABC), s)

		// Length remaining = 4 (chunkLen header) + 3 (xyz) = 7.
		rem := beaconDataLengthImpl(uintptr(unsafe.Pointer(&p)))
		assert.Equal(t, uintptr(7), rem)

		// Extract — pulls the length-prefixed bytes; outLen written.
		var outLen int32
		dataPtr := beaconDataExtractImpl(uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&outLen)))
		require.NotZero(t, dataPtr)
		assert.Equal(t, int32(3), outLen)
		got := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), int(outLen))
		assert.Equal(t, []byte("xyz"), got)

		// Buffer fully drained.
		assert.Equal(t, uintptr(0), beaconDataLengthImpl(uintptr(unsafe.Pointer(&p))))
	})
}

func TestBeaconDataParse_NilParser(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		// A nil parser pointer is a hostile input — must not panic.
		ret := beaconDataParseImpl(0, 0, 0)
		assert.Zero(t, ret)
	})
}

// TestRelocationConstants is a regression guard locking the COFF AMD64
// relocation type values against the PE spec. A typo flipping one
// constant by a single digit would silently mis-route every BOF
// relocation; this test catches that the constants match the
// canonical IMAGE_REL_AMD64_* numeric values.
// TestBeaconFormat_RoundTrip exercises the full Alloc → Append → Int →
// ToString → Free cycle. Asserts the bytes the BOF reads back match
// what we wrote, and that Free clears the formatp fields.
func TestBeaconFormat_RoundTrip(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		var fmt formatp
		beaconFormatAllocImpl(uintptr(unsafe.Pointer(&fmt)), 64)
		require.NotZero(t, fmt.original)
		require.Equal(t, int32(64), fmt.size)
		require.Equal(t, int32(0), fmt.length)

		// Append "hi" then a big-endian int 0xCAFEBABE.
		hi := []byte("hi")
		beaconFormatAppendImpl(
			uintptr(unsafe.Pointer(&fmt)),
			uintptr(unsafe.Pointer(&hi[0])),
			uintptr(len(hi)),
		)
		assert.Equal(t, int32(2), fmt.length)

		beaconFormatIntImpl(uintptr(unsafe.Pointer(&fmt)), 0xCAFEBABE)
		assert.Equal(t, int32(6), fmt.length)

		// ToString returns the original pointer and writes length.
		var outLen int32
		ptr := beaconFormatToStringImpl(
			uintptr(unsafe.Pointer(&fmt)),
			uintptr(unsafe.Pointer(&outLen)),
		)
		require.Equal(t, fmt.original, ptr)
		assert.Equal(t, int32(6), outLen)

		got := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(outLen))
		assert.Equal(t, []byte{'h', 'i', 0xCA, 0xFE, 0xBA, 0xBE}, got)

		// Reset rewinds the cursor without releasing the slice.
		beaconFormatResetImpl(uintptr(unsafe.Pointer(&fmt)))
		assert.Equal(t, int32(0), fmt.length)
		assert.Equal(t, fmt.original, fmt.buffer)

		// Free clears the formatp fields.
		beaconFormatFreeImpl(uintptr(unsafe.Pointer(&fmt)))
		assert.Equal(t, uintptr(0), fmt.original)
		assert.Equal(t, int32(0), fmt.size)
	})
}

func TestBeaconFormatAppend_Truncates(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		var fmt formatp
		beaconFormatAllocImpl(uintptr(unsafe.Pointer(&fmt)), 4)
		// Write 8 bytes into a 4-byte buffer — append truncates silently.
		src := []byte("ABCDEFGH")
		beaconFormatAppendImpl(
			uintptr(unsafe.Pointer(&fmt)),
			uintptr(unsafe.Pointer(&src[0])),
			uintptr(len(src)),
		)
		assert.Equal(t, int32(4), fmt.length)
		got := unsafe.Slice((*byte)(unsafe.Pointer(fmt.original)), 4)
		assert.Equal(t, []byte("ABCD"), got)
		beaconFormatFreeImpl(uintptr(unsafe.Pointer(&fmt)))
	})
}

func TestBeaconFormatAlloc_NilGuards(t *testing.T) {
	// Hostile inputs must not panic.
	assert.Equal(t, uintptr(0), beaconFormatAllocImpl(0, 16))
	var fmt formatp
	assert.Equal(t, uintptr(0), beaconFormatAllocImpl(uintptr(unsafe.Pointer(&fmt)), 0))
}

// TestBeaconFormatPrintf_VerbatimAppend — varargs aren't expandable from
// a NewCallback thunk; the implementation forwards the format string
// verbatim. Test asserts the bytes land in the format buffer.
func TestBeaconFormatPrintf_VerbatimAppend(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		var fmt formatp
		beaconFormatAllocImpl(uintptr(unsafe.Pointer(&fmt)), 64)
		fmtStr := []byte("hello %d\x00")
		beaconFormatPrintfImpl(
			uintptr(unsafe.Pointer(&fmt)),
			uintptr(unsafe.Pointer(&fmtStr[0])),
		)
		// Verbatim — the %d stays as-is. CS BOFs that pass a literal
		// format string see this as the shipped behaviour.
		got := unsafe.Slice((*byte)(unsafe.Pointer(fmt.original)), int(fmt.length))
		assert.Equal(t, []byte("hello %d"), got)
		beaconFormatFreeImpl(uintptr(unsafe.Pointer(&fmt)))
	})
}

// TestBeaconError_RoutesToErrorsBuffer — BeaconErrorD/DD/NA must write
// into b.errors, not b.output. Asserts both buffers stay separate.
func TestBeaconError_RoutesToErrorsBuffer(t *testing.T) {
	withCurrentBOF(t, func(b *BOF) {
		beaconErrorDImpl(7, 42)
		beaconErrorDDImpl(8, 100, 200)
		beaconErrorNAImpl(9)

		// Errors buffer carries the formatted lines.
		errs := b.Errors()
		assert.Contains(t, string(errs), "type=7 data=42")
		assert.Contains(t, string(errs), "type=8 data1=100 data2=200")
		assert.Contains(t, string(errs), "type=9\n")

		// Output buffer must stay empty — the two channels are isolated.
		assert.Empty(t, b.output.Bytes())
	})
}

func TestBeaconError_NoCurrentBOF(t *testing.T) {
	bofMu.Lock()
	defer bofMu.Unlock()
	currentBOF = nil
	// Each variant must no-op safely when no BOF context is active.
	assert.Equal(t, uintptr(0), beaconErrorDImpl(1, 2))
	assert.Equal(t, uintptr(0), beaconErrorDDImpl(1, 2, 3))
	assert.Equal(t, uintptr(0), beaconErrorNAImpl(1))
}

func TestBeaconGetSpawnTo_ReturnsConfiguredPath(t *testing.T) {
	withCurrentBOF(t, func(b *BOF) {
		b.SetSpawnTo(`C:\Windows\System32\rundll32.exe`)
		ptr := beaconGetSpawnToImpl(0, 0)
		require.NotZero(t, ptr)
		got := cStringFromPtr(ptr, 256)
		assert.Equal(t, `C:\Windows\System32\rundll32.exe`, got)
	})
}

func TestBeaconGetSpawnTo_EmptyByDefault(t *testing.T) {
	withCurrentBOF(t, func(_ *BOF) {
		// No SetSpawnTo call → returns 0 (BOF sees null pointer).
		assert.Equal(t, uintptr(0), beaconGetSpawnToImpl(0, 0))
	})
}

// TestBOF_Errors_NilBeforeExecute — Errors() must return nil before
// Execute initialises the buffer.
func TestBOF_Errors_NilBeforeExecute(t *testing.T) {
	b := &BOF{}
	assert.Nil(t, b.Errors())
}

// TestBOF_SetSpawnTo_RoundTrip — SetSpawnTo configures the path; the
// pinned C-string includes the trailing NUL.
func TestBOF_SetSpawnTo_RoundTrip(t *testing.T) {
	b := &BOF{}
	b.SetSpawnTo("foo.exe")
	require.NotNil(t, b.spawnToCStr)
	assert.Equal(t, []byte{'f', 'o', 'o', '.', 'e', 'x', 'e', 0}, b.spawnToCStr)

	// SetSpawnTo("") clears.
	b.SetSpawnTo("")
	assert.Nil(t, b.spawnToCStr)
}

// TestNewBeaconAPI_SymbolsRegistered — sanity check that every new
// callback name resolves to a non-zero callback address. Catches a
// typo in initBeaconCallbacks that would slip past the per-stub
// tests above.
func TestNewBeaconAPI_SymbolsRegistered(t *testing.T) {
	for _, name := range []string{
		"__imp_BeaconFormatPrintf",
		"__imp_BeaconErrorD",
		"__imp_BeaconErrorDD",
		"__imp_BeaconErrorNA",
		"__imp_BeaconGetSpawnTo",
	} {
		addr, ok := resolveBeaconImport(name)
		require.True(t, ok, "%s must resolve", name)
		assert.NotZero(t, addr)
	}
}

// TestRelocationConstants is a regression guard locking the COFF AMD64
// relocation type values against the PE spec. A typo flipping one
// constant by a single digit would silently mis-route every BOF
// relocation; this test catches that the constants match the
// canonical IMAGE_REL_AMD64_* numeric values.
func TestRelocationConstants(t *testing.T) {
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"ABSOLUTE", imageRelAMD64Absolute, 0x0000},
		{"ADDR64", imageRelAMD64Addr64, 0x0001},
		{"ADDR32", imageRelAMD64Addr32, 0x0002},
		{"ADDR32NB", imageRelAMD64Addr32NB, 0x0003},
		{"REL32", imageRelAMD64Rel32, 0x0004},
		{"REL32_1", imageRelAMD64Rel32Plus1, 0x0005},
		{"REL32_2", imageRelAMD64Rel32Plus2, 0x0006},
		{"REL32_3", imageRelAMD64Rel32Plus3, 0x0007},
		{"REL32_4", imageRelAMD64Rel32Plus4, 0x0008},
		{"REL32_5", imageRelAMD64Rel32Plus5, 0x0009},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.got, "IMAGE_REL_AMD64_%s", c.name)
	}
}

func TestCStringFromPtr(t *testing.T) {
	src := []byte("text\x00ignored")
	got := cStringFromPtr(uintptr(unsafe.Pointer(&src[0])), 16)
	assert.Equal(t, "text", got)
	assert.Empty(t, cStringFromPtr(0, 16))
}
