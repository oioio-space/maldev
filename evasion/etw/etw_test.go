//go:build windows

package etw

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

func TestPatch(t *testing.T) {
	testutil.RequireIntrusive(t)
	proc := api.Ntdll.NewProc("EtwEventWrite")
	if err := proc.Find(); err != nil {
		t.Fatal("EtwEventWrite not found")
	}
	addr := proc.Addr()
	err := Patch(nil)
	require.NoError(t, err)
	patched := (*[4]byte)(unsafe.Pointer(addr))
	assert.Equal(t, byte(0x48), patched[0])
	assert.Equal(t, byte(0x33), patched[1])
	assert.Equal(t, byte(0xC0), patched[2])
	assert.Equal(t, byte(0xC3), patched[3])
}
