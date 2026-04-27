//go:build windows

package drive_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/recon/drive"
)

// New resolves a single drive letter and returns its full
// volume metadata (type, label, serial, filesystem).
func ExampleNew() {
	d, err := drive.New("C:")
	if err != nil {
		return
	}
	fmt.Printf("%s %s\n", d.Letter, d.Type)
}

// NewWatcher polls for newly connected drives — useful for
// USB-key insertion triggers and removable-media data
// staging.
func ExampleNewWatcher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := drive.NewWatcher(ctx, func(d *drive.Info) bool {
		return d.Type == drive.TypeRemovable
	})
	ch, err := w.Watch(200 * time.Millisecond)
	if err != nil {
		return
	}
	for ev := range ch {
		if ev.Kind == drive.EventAdded {
			fmt.Printf("inserted: %s\n", ev.Drive.Letter)
		}
	}
}
