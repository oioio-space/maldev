//go:build windows

package clipboard_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/collection/clipboard"
)

// ReadText returns the current clipboard text in a single call.
func ExampleReadText() {
	text, err := clipboard.ReadText()
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Println(text)
}

// Watch polls the clipboard at the given interval and streams text
// changes until the context is cancelled.
func ExampleWatch() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch := clipboard.Watch(ctx, 200*time.Millisecond)
	for text := range ch {
		fmt.Println("clipboard:", text)
	}
}
