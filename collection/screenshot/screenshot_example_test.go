//go:build windows

package screenshot_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/collection/screenshot"
)

// Capture grabs the primary display and returns PNG bytes.
func ExampleCapture() {
	png, err := screenshot.Capture()
	if err != nil {
		fmt.Println("capture:", err)
		return
	}
	_ = os.WriteFile("primary.png", png, 0o644)
	fmt.Printf("size: %d bytes\n", len(png))
}

// Multi-monitor capture — enumerate displays, capture each.
func ExampleCaptureDisplay() {
	for i := 0; i < screenshot.DisplayCount(); i++ {
		bounds := screenshot.DisplayBounds(i)
		png, err := screenshot.CaptureDisplay(i)
		if err != nil {
			fmt.Printf("display %d: %v\n", i, err)
			continue
		}
		fmt.Printf("display %d (%dx%d): %d bytes\n",
			i, bounds.Dx(), bounds.Dy(), len(png))
	}
}

// CaptureRect crops to an arbitrary screen rectangle.
func ExampleCaptureRect() {
	png, _ := screenshot.CaptureRect(0, 0, 800, 600)
	fmt.Printf("size: %d bytes\n", len(png))
}
