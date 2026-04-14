//go:build windows

package keylog

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
)

func TestStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := Start(ctx)
	require.NoError(t, err)
	assert.NotNil(t, ch)

	// Clean up so other tests can run.
	cancel()

	// Wait for channel close to confirm teardown.
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("channel not closed after context cancel")
	}
}

// sendKey simulates a key press+release via SendInput.
func sendKey(vk uint16) {
	inputs := [2]keyboardInput{
		{inputType: 1, ki: keybdInput{wVk: vk}},
		{inputType: 1, ki: keybdInput{wVk: vk, dwFlags: 0x0002}}, // KEYEVENTF_KEYUP
	}
	sendInputProc.Call(2, uintptr(unsafe.Pointer(&inputs[0])), unsafe.Sizeof(inputs[0]))
}

var sendInputProc = api.User32.NewProc("SendInput")

type keybdInput struct {
	wVk         uint16
	wScan       uint16
	dwFlags     uint32
	time        uint32
	dwExtraInfo uintptr
}

type keyboardInput struct {
	inputType uint32
	ki        keybdInput
	_         [8]byte // padding to match MOUSEINPUT size
}

// TestCaptureSimulatedKeystrokes installs the hook, simulates key presses via
// SendInput, and verifies the events appear on the channel.
func TestCaptureSimulatedKeystrokes(t *testing.T) {
	testutil.RequireIntrusive(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := Start(ctx)
	require.NoError(t, err)

	// Give the hook time to install and the message loop to start.
	time.Sleep(200 * time.Millisecond)

	// Simulate pressing 'A' (VK_A = 0x41).
	sendKey(0x41)

	// Wait for the event.
	var captured []Event
	timeout := time.After(3 * time.Second)
	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				goto done
			}
			captured = append(captured, evt)
			if len(captured) >= 1 {
				goto done
			}
		case <-timeout:
			goto done
		}
	}
done:
	cancel()
	// Wait for the hook goroutine to unregister the global singleton.
	// Without this, the next test calling Start() gets ErrAlreadyRunning.
	time.Sleep(500 * time.Millisecond)

	if len(captured) == 0 {
		t.Skip("no keystrokes captured — may need interactive desktop session")
	}
	assert.Equal(t, 0x41, captured[0].KeyCode, "expected VK_A (0x41)")
	t.Logf("captured %d events, first: keycode=0x%X char=%q", len(captured), captured[0].KeyCode, captured[0].Character)
}

func TestStartCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := Start(ctx)
	require.NoError(t, err)

	// Channel must close when the context expires.
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // success -- channel closed
			}
		case <-timeout:
			t.Fatal("channel not closed after context timeout")
		}
	}
}
