package timing_test

import (
	"time"

	"github.com/oioio-space/maldev/recon/timing"
)

// BusyWait burns CPU for a real wall-clock duration —
// defeats sandboxes that fast-forward Sleep(). The CPU
// pattern is a tight time-comparison loop.
func ExampleBusyWait() {
	timing.BusyWait(15 * time.Second)
}

// BusyWaitPrimality burns CPU via primality testing — same
// wall-clock effect as BusyWait but with a more "math-like"
// CPU pattern that blends with legitimate workloads.
func ExampleBusyWaitPrimality() {
	timing.BusyWaitPrimality()
}
