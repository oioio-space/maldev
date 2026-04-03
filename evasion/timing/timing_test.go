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

func TestBusyWaitPrimalityN_Zero(t *testing.T) {
	start := time.Now()
	BusyWaitPrimalityN(0)
	elapsed := time.Since(start)
	if elapsed > 10*time.Millisecond {
		t.Fatalf("BusyWaitPrimalityN(0) should return immediately, took %v", elapsed)
	}
}

func TestBusyWaitPrimalityN_Small(t *testing.T) {
	start := time.Now()
	BusyWaitPrimalityN(100)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("BusyWaitPrimalityN(100) took too long: %v", elapsed)
	}
}

func TestBusyWaitTrig(t *testing.T) {
	start := time.Now()
	BusyWaitTrig(50 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("BusyWaitTrig returned too early: %v", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("BusyWaitTrig took too long: %v", elapsed)
	}
}

func TestBusyWaitTrig_Zero(t *testing.T) {
	start := time.Now()
	BusyWaitTrig(0)
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("BusyWaitTrig(0) should return nearly immediately, took %v", elapsed)
	}
}

func TestBusyWaitPrimalityN_Proportional(t *testing.T) {
	start := time.Now()
	BusyWaitPrimalityN(1000)
	small := time.Since(start)

	start = time.Now()
	BusyWaitPrimalityN(50000)
	large := time.Since(start)

	if large <= small {
		t.Fatalf("expected BusyWaitPrimalityN(50000) > BusyWaitPrimalityN(1000), got %v <= %v", large, small)
	}
}
