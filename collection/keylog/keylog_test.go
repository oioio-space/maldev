//go:build windows

package keylog

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
