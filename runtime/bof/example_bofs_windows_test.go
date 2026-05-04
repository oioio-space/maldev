//go:build windows

package bof

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

// loadExampleBOF reads a .o file from runtime/bof/testdata. The path
// is relative because go test sets the working directory to the
// package dir on Windows VMs.
func loadExampleBOF(t *testing.T, name string) []byte {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	require.NoError(t, err)
	data, err := os.ReadFile(abs)
	require.NoError(t, err, "missing testdata/%s — build with mingw-w64 (see testdata/README.md)", name)
	return data
}

// TestExecute_HelloBeacon_E2E loads testdata/hello_beacon.o, executes
// it, and asserts the BOF emitted "hello from BOF\n" via BeaconPrintf.
// End-to-end coverage for: COFF parser → .text RWX allocation →
// Beacon API stub resolution (__imp_BeaconPrintf) → relocation patch
// → entry call → output capture.
func TestExecute_HelloBeacon_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "hello_beacon.o")
	b, err := Load(data)
	require.NoError(t, err)

	out, err := b.Execute(nil)
	require.NoError(t, err)
	assert.Contains(t, string(out), "hello from BOF",
		"BOF output must contain the BeaconPrintf greeting; got %q", string(out))
}

// TestExecute_ParseArgs_E2E packs (int, string) via the loader's Args
// helper, executes parse_args.o, and asserts the BOF observed the
// string back via BeaconDataExtract → BeaconPrintf.
func TestExecute_ParseArgs_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "parse_args.o")
	b, err := Load(data)
	require.NoError(t, err)

	args := NewArgs()
	args.AddInt(42)
	args.AddString("hello-args")

	out, err := b.Execute(args.Pack())
	require.NoError(t, err)
	assert.Contains(t, string(out), "parsed args:")
	assert.Contains(t, string(out), "hello-args",
		"BOF must echo the AddString payload via BeaconDataExtract; got %q", string(out))
}

// TestExecute_FormatOutput_E2E loads format_output.o and asserts the
// BeaconFormat family + BeaconOutput + the bare-form __imp_<func>
// resolver all reached the wire correctly. The BOF builds "tag=" + a
// 4-byte BE int (current PID, queried via the bare-form
// GetCurrentProcessId import) inside a format buffer, ships the bytes
// via BeaconOutput, and emits a trailer marker via BeaconPrintf.
func TestExecute_FormatOutput_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "format_output.o")
	b, err := Load(data)
	require.NoError(t, err)

	out, err := b.Execute(nil)
	require.NoError(t, err)

	assert.Contains(t, string(out), "format_output done",
		"BOF must emit the trailer marker via BeaconPrintf; got %q", string(out))

	idx := bytes.Index(out, []byte("tag="))
	require.GreaterOrEqual(t, idx, 0, "output must contain the format-buffer tag prefix; got %q", string(out))
	require.GreaterOrEqual(t, len(out)-idx, 4+4, "output truncated before the BE int payload")

	gotPID := binary.BigEndian.Uint32(out[idx+4 : idx+8])
	wantPID := windows.GetCurrentProcessId()
	assert.Equal(t, wantPID, gotPID,
		"BeaconFormatInt must round-trip the BE-encoded PID; got %d, want %d", gotPID, wantPID)
}

// TestExecute_ErrorSpawnTo_E2E loads error_spawnto.o and asserts the
// errors-channel routing (BeaconErrorD → (*BOF).Errors()) and the
// SetSpawnTo / BeaconGetSpawnTo round-trip.
func TestExecute_ErrorSpawnTo_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "error_spawnto.o")
	b, err := Load(data)
	require.NoError(t, err)

	b.SetSpawnTo("notepad.exe")

	out, err := b.Execute(nil)
	require.NoError(t, err)

	assert.Contains(t, string(out), "spawn-to=notepad.exe",
		"BeaconGetSpawnTo must echo the SetSpawnTo path; got output %q", string(out))

	errs := string(b.Errors())
	assert.Contains(t, errs, "error type=7 data=42",
		"BeaconErrorD must populate the per-BOF errors buffer; got errors %q", errs)
	assert.NotContains(t, string(out), "error type=",
		"errors must not bleed into the output channel; got output %q", string(out))
}

// TestExecute_DataExtras_E2E loads data_extras.o and asserts the BOF
// observed BeaconDataLength + BeaconDataShort behaving as advertised
// across the LE wire format. Caller packs (short=0x1234, string="hi")
// — total args length = 2 + 4 + 3 = 9 bytes. The BOF reports
// [len_before, short_value, len_after] as three BE ints inside a
// format buffer; we decode and compare.
func TestExecute_DataExtras_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "data_extras.o")
	b, err := Load(data)
	require.NoError(t, err)

	args := NewArgs()
	args.AddShort(0x1234)
	args.AddString("hi")
	packed := args.Pack()
	require.Len(t, packed, 9, "wire format guard — must match the BOF's expected layout")

	out, err := b.Execute(packed)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(out), 12, "output must contain 3 BE ints; got %q", string(out))
	lenBefore := binary.BigEndian.Uint32(out[0:4])
	shortVal := binary.BigEndian.Uint32(out[4:8])
	lenAfter := binary.BigEndian.Uint32(out[8:12])

	assert.Equal(t, uint32(9), lenBefore, "BeaconDataLength before consume must equal total wire length")
	assert.Equal(t, uint32(0x1234), shortVal, "BeaconDataShort must read the AddShort value via LE")
	assert.Equal(t, uint32(7), lenAfter, "BeaconDataLength after must equal total - 2 (short consumed)")

	assert.Contains(t, string(out), "data_extras done",
		"BOF must reach the trailer marker; got %q", string(out))
}

// TestExecute_FormatExtras_E2E loads format_extras.o and asserts:
//   - BeaconFormatReset rewinds the cursor (the "first" payload no
//     longer appears in the ToString result).
//   - BeaconFormatPrintf appends verbatim (the "after-reset" payload
//     reaches BeaconOutput intact).
//   - BeaconErrorDD / BeaconErrorNA route to the per-BOF errors
//     channel with the expected formatting.
func TestExecute_FormatExtras_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "format_extras.o")
	b, err := Load(data)
	require.NoError(t, err)

	out, err := b.Execute(nil)
	require.NoError(t, err)

	assert.True(t, bytes.HasPrefix(out, []byte("after-reset")),
		"output must start with the post-reset payload; got %q", string(out))
	assert.NotContains(t, string(out), "first",
		"FormatReset must drop the pre-reset payload from ToString; got %q", string(out))
	assert.Contains(t, string(out), "format_extras done",
		"BOF must reach the trailer marker; got %q", string(out))

	errs := string(b.Errors())
	assert.Contains(t, errs, "error type=3 data1=11 data2=22",
		"BeaconErrorDD must populate the errors buffer; got %q", errs)
	assert.Contains(t, errs, "error type=5",
		"BeaconErrorNA must populate the errors buffer; got %q", errs)
	assert.NotContains(t, string(out), "error type=",
		"errors must not bleed into the output channel; got %q", string(out))
}

// TestExecute_LoadLib_E2E exercises the dollar-import resolver path
// end-to-end: the BOF imports kernel32!LoadLibraryA + FreeLibrary via
// the __imp_<DLL>$<Func> notation, loads/unloads crypt32.dll, prints
// status. Asserts the loader resolved the dynamic-link imports
// against the real kernel32 entry points (no GetProcAddress import
// in the BOF's COFF symbol table beyond the dollar-import names).
func TestExecute_LoadLib_E2E(t *testing.T) {
	testutil.RequireIntrusive(t)
	data := loadExampleBOF(t, "loadlib.o")
	b, err := Load(data)
	require.NoError(t, err)

	out, err := b.Execute(nil)
	require.NoError(t, err)
	got := string(out)
	// Either path is acceptable: the load succeeds (most likely on
	// any Windows host) or the BOF surfaces the NULL fallback. Both
	// prove the dollar-import resolution + the call path landed.
	if !strings.Contains(got, "crypt32.dll loaded") &&
		!strings.Contains(got, "LoadLibraryA(crypt32.dll) returned NULL") {
		t.Fatalf("BOF output didn't match either branch: %q", got)
	}
}
