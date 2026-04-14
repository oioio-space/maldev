//go:build windows

package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestReadText(t *testing.T) {
	// Clipboard content is unpredictable and may be locked by another
	// process; just verify no crash/panic. ErrOpen is acceptable when
	// the clipboard is in use or unavailable in non-interactive contexts.
	text, err := ReadText()
	if errors.Is(err, ErrOpen) {
		t.Log("clipboard unavailable (locked or non-interactive session)")
		return
	}
	assert.NoError(t, err)
	t.Logf("clipboard text length: %d", len(text))
}

// TestReadTextRoundtrip sets clipboard content via PowerShell, then reads it back.
func TestReadTextRoundtrip(t *testing.T) {
	testutil.RequireIntrusive(t)

	marker := "MALDEV_CLIP_" + fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	// Set clipboard via PowerShell (reliable, uses COM underneath).
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Set-Clipboard -Value '%s'", marker))
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot set clipboard (non-interactive session?): %v", err)
	}

	text, err := ReadText()
	require.NoError(t, err)
	assert.Equal(t, marker, text, "clipboard roundtrip must return the exact string we set")
}

func TestWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	ch := Watch(ctx, 100*time.Millisecond)
	assert.NotNil(t, ch)

	// Wait for channel close to confirm clean teardown.
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // success
			}
		case <-timeout:
			t.Fatal("channel not closed after context timeout")
		}
	}
}
