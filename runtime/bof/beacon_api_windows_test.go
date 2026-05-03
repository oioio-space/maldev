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
