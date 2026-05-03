//go:build windows

package bof

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
