//go:build windows

package clipboard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
