package timing

import (
	"testing"
	"time"
)

func TestBusyWait(t *testing.T) {
	start := time.Now()
	BusyWait(50 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("BusyWait returned too early: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("BusyWait took too long: %v", elapsed)
	}
}

func TestBusyWaitZero(t *testing.T) {
	start := time.Now()
	BusyWait(0)
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("BusyWait(0) should return nearly immediately, took %v", elapsed)
	}
}

func TestBusyWaitPrimality(t *testing.T) {
	start := time.Now()
	BusyWaitPrimality()
	elapsed := time.Since(start)
	// Should take at least a few ms and not more than 10 seconds
	if elapsed < time.Millisecond {
		t.Fatal("BusyWaitPrimality returned too fast")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("BusyWaitPrimality took too long: %v", elapsed)
	}
}
