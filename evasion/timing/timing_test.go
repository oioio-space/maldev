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
	// BusyWaitPrimality's workload is fixed — the upper bound is a sanity
	// check against an infinite loop, not a performance SLA. VMs with
	// shared-CPU allocation and no host pinning can take 20-30s for work
	// that finishes in 5s on bare metal, so the bound is intentionally
	// generous to stay green on the test matrix (Windows VM 20 vCPUs /
	// 4GB RAM has been observed >10s).
	if elapsed < time.Millisecond {
		t.Fatal("BusyWaitPrimality returned too fast")
	}
	if elapsed > 60*time.Second {
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
