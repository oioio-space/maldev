//go:build windows

package service

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// requireManual skips unless MALDEV_MANUAL=1 is set.
func requireManual(t *testing.T) {
	t.Helper()
	if os.Getenv("MALDEV_MANUAL") == "" {
		t.Skip("manual test: set MALDEV_MANUAL=1 (requires admin + VM)")
	}
}

// TestHideService modifies the DACL of a test service to make it inaccessible
// to non-SYSTEM users.
//
// PREREQUISITES:
//   - Run as Administrator
//   - Run in a VM
//   - Create a test service first:
//     sc create MaldevTestSvc binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= demand
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./cleanup/service/ -run TestHideService -v
//
// VERIFY:
//
//	sc sdshow MaldevTestSvc — should show the restrictive DACL
//	sc query MaldevTestSvc — may fail with Access Denied for non-SYSTEM users
//
// CLEANUP:
//
//	sc delete MaldevTestSvc
//	Or restart the VM.
func TestHideService(t *testing.T) {
	requireManual(t)
	testutil.RequireIntrusive(t)

	const svcName = "MaldevTestSvc"

	// Use Native mode (direct Windows API) to apply the restrictive DACL.
	output, err := HideService(Native, "", svcName)
	require.NoError(t, err)
	t.Logf("HideService output: %q", output)

	t.Log("service DACL restricted; run 'sc sdshow MaldevTestSvc' to verify")
}

// TestUnHideService restores the default DACL on MaldevTestSvc after TestHideService.
//
// PREREQUISITES:
//   - Run as Administrator
//   - Run in a VM
//   - MaldevTestSvc must exist and have been hidden by TestHideService
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./cleanup/service/ -run TestUnHideService -v
//
// VERIFY:
//
//	sc sdshow MaldevTestSvc — should show the default DACL
//	sc query MaldevTestSvc — should succeed for standard users
//
// CLEANUP:
//
//	sc delete MaldevTestSvc
func TestUnHideService(t *testing.T) {
	requireManual(t)
	testutil.RequireIntrusive(t)

	const svcName = "MaldevTestSvc"

	output, err := UnHideService(Native, "", svcName)
	require.NoError(t, err)
	t.Logf("UnHideService output: %q", output)

	t.Log("service DACL restored to default")
}

// TestHideServiceSCSdset applies the restrictive DACL using sc.exe SDSET.
//
// PREREQUISITES:
//   - Run as Administrator
//   - Run in a VM
//   - Create a test service first:
//     sc create MaldevTestSvc binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= demand
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./cleanup/service/ -run TestHideServiceSCSdset -v
//
// VERIFY:
//
//	sc sdshow MaldevTestSvc — should show the restrictive DACL
//
// CLEANUP:
//
//	sc delete MaldevTestSvc
func TestHideServiceSCSdset(t *testing.T) {
	requireManual(t)
	testutil.RequireIntrusive(t)

	const svcName = "MaldevTestSvc"

	output, err := HideService(SC_SDSET, "", svcName)
	require.NoError(t, err)
	assert.NotEmpty(t, output, "sc.exe should produce output")
	t.Logf("sc sdset output: %s", output)
}
