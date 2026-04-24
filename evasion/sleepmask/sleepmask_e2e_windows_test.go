//go:build windows

// End-to-end tests that prove the sleep-mask technique actually works —
// not just that bytes round-trip, but that a concurrent memory scanner
// targeting executable pages stops finding the protected region during
// sleep, and that page permissions are genuinely downgraded and restored.
//
// These tests mirror the "concrete examples" shown in
// docs/techniques/evasion/sleep-mask.md.

package sleepmask

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

// e2eStrategies lists every strategy the e2e suite asserts the
// "masked window is opaque" invariant against. Extended as new
// strategies are shipped.
//
// Each entry may pin a specific cipher (for strategies that require
// one — EkkoStrategy only works with RC4). cipher=nil keeps the
// Mask's default XOR cipher.
func e2eStrategies() []struct {
	name   string
	ctor   func() Strategy
	cipher Cipher
} {
	return []struct {
		name   string
		ctor   func() Strategy
		cipher Cipher
	}{
		{"inline", func() Strategy { return &InlineStrategy{} }, nil},
		{"timerqueue", func() Strategy { return &TimerQueueStrategy{} }, nil},
		{"ekko", func() Strategy { return &EkkoStrategy{} }, NewRC4Cipher()},
	}
}

// allocAndWriteRX allocates a region, writes payload, flips it to
// PAGE_EXECUTE_READ (the usual "post-inject" state), and returns the base
// address plus a cleanup func.
func allocAndWriteRX(t *testing.T, payload []byte) (uintptr, func()) {
	t.Helper()
	size := uintptr(len(payload))
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	require.NoError(t, err)

	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload)), payload)

	var old uint32
	require.NoError(t, windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &old))

	return addr, func() { _ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE) }
}

// queryProtect returns the current page protection for addr.
func queryProtect(t *testing.T, addr uintptr) uint32 {
	t.Helper()
	var mbi windows.MemoryBasicInformation
	err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi))
	require.NoError(t, err)
	return mbi.Protect
}

// TestSleepMaskE2E_DefeatsExecutablePageScanner is the canonical proof that
// the technique works: a 19-byte canary with the ASCII marker
// "MALDEV_CANARY!!\n" sits in a PAGE_EXECUTE_READ region. A baseline
// pre-mask scan with testutil.ScanProcessMemory (which only inspects
// executable pages, like an EDR memory scanner does) must find it. During
// Sleep(), a concurrent scanner must fail to find it, because the mask has
// both XOR-scrambled the bytes AND dropped the executable bit. After the
// sleep returns, the canary must be findable again.
func TestSleepMaskE2E_DefeatsExecutablePageScanner(t *testing.T) {
	for _, strat := range e2eStrategies() {
		strat := strat
		t.Run(strat.name, func(t *testing.T) {
			testDefeatsExecutablePageScanner(t, strat.ctor(), strat.cipher)
		})
	}
}

func testDefeatsExecutablePageScanner(t *testing.T, strategy Strategy, cipher Cipher) {
	payload := testutil.WindowsSearchableCanary
	addr, cleanup := allocAndWriteRX(t, payload)
	defer cleanup()

	// Baseline: marker is findable on an executable page.
	marker := []byte("MALDEV_CANARY!!\n")
	found, ok := testutil.ScanProcessMemory(marker)
	require.True(t, ok, "baseline scan must find canary before masking")
	require.Equal(t, addr+3, found, "canary marker should sit 3 bytes after base (past xor eax/ret)")

	mask := New(Region{Addr: addr, Size: uintptr(len(payload))}).WithStrategy(strategy)
	if cipher != nil {
		mask = mask.WithCipher(cipher)
	}

	// The scanner counts a hit only when the mask was engaged for the
	// ENTIRE scan pass. Three windows exist during mask.Sleep:
	//   1. Pre-mask: page is still RX, canary legitimately findable.
	//   2. Masked window: page is RW, canary scrambled. This is the
	//      only window we care about.
	//   3. Post-mask (decrypt): page flips RW → RX while bytes are
	//      decrypted; on the transition the scanner could race the
	//      protection flip and match the restored canary on a newly-RX
	//      page.
	// Sampling protection only at the TOP of the pass is not enough
	// because the scan itself takes time and the protection can change
	// during the walk. We sample before AND after and count the pass
	// only if protection is RW at both edges. This pins the property
	// "once masked and for as long as masked, the scanner is blind".
	var scanHits int32
	var scanAttempts int32
	stopScan := make(chan struct{})
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		for {
			select {
			case <-stopScan:
				return
			default:
			}
			if queryProtect(t, addr) != windows.PAGE_READWRITE {
				time.Sleep(500 * time.Microsecond)
				continue
			}
			_, hit := testutil.ScanProcessMemory(marker)
			if queryProtect(t, addr) != windows.PAGE_READWRITE {
				// Protection flipped during the scan — discard this pass.
				continue
			}
			atomic.AddInt32(&scanAttempts, 1)
			if hit {
				atomic.AddInt32(&scanHits, 1)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	mask.Sleep(context.Background(), 300 * time.Millisecond)
	close(stopScan)
	<-scanDone

	hits := atomic.LoadInt32(&scanHits)
	attempts := atomic.LoadInt32(&scanAttempts)
	assert.Zero(t, hits,
		"concurrent scanner must NOT find canary on executable pages during masked sleep (hits=%d / attempts=%d)",
		hits, attempts)
	assert.Greater(t, attempts, int32(5), "scanner must have run several passes during the masked window (got %d)", attempts)

	// After sleep: canary is back on an executable page.
	_, ok = testutil.ScanProcessMemory(marker)
	assert.True(t, ok, "canary must be findable again after masked sleep returns")
}

// TestSleepMaskE2E_RestoresOriginalRXProtection proves that a region set to
// PAGE_EXECUTE_READ before masking is returned to PAGE_EXECUTE_READ after.
// During the sleep, the region must be RW (no executable bit).
func TestSleepMaskE2E_RestoresOriginalRXProtection(t *testing.T) {
	addr, cleanup := allocAndWriteRX(t, testutil.WindowsCanaryX64)
	defer cleanup()

	require.Equal(t, uint32(windows.PAGE_EXECUTE_READ), queryProtect(t, addr))

	mask := New(Region{Addr: addr, Size: uintptr(len(testutil.WindowsCanaryX64))})

	// Sample protection mid-sleep from a goroutine.
	var midProtect uint32
	sampled := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		midProtect = queryProtect(t, addr)
		close(sampled)
	}()

	mask.Sleep(context.Background(), 200 * time.Millisecond)
	<-sampled

	assert.Equal(t, uint32(windows.PAGE_READWRITE), midProtect,
		"mid-sleep protection must be PAGE_READWRITE, got 0x%X", midProtect)
	assert.Equal(t, uint32(windows.PAGE_EXECUTE_READ), queryProtect(t, addr),
		"protection must be restored to PAGE_EXECUTE_READ after sleep returns")
}

// TestSleepMaskE2E_RestoresOriginalRWXProtection proves that an RWX region
// is returned to RWX (not collapsed to RX) after a mask cycle.
func TestSleepMaskE2E_RestoresOriginalRWXProtection(t *testing.T) {
	size := uintptr(64)
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	require.Equal(t, uint32(windows.PAGE_EXECUTE_READWRITE), queryProtect(t, addr))

	mask := New(Region{Addr: addr, Size: size})
	mask.Sleep(context.Background(), 20 * time.Millisecond)

	assert.Equal(t, uint32(windows.PAGE_EXECUTE_READWRITE), queryProtect(t, addr),
		"RWX region must stay RWX after sleep (not collapsed to RX)")
}

// TestSleepMaskE2E_MultiRegionIndependentEncryption proves that multiple
// non-contiguous regions are all encrypted during sleep and all restored
// byte-for-byte after. Each region has a distinct searchable marker.
func TestSleepMaskE2E_MultiRegionIndependentEncryption(t *testing.T) {
	regionA := []byte("MALDEV_REGION_A_MARKER_AAAAAAAAA")
	regionB := []byte("MALDEV_REGION_B_MARKER_BBBBBBBBB")

	addrA, cleanupA := allocAndWriteRX(t, regionA)
	defer cleanupA()
	addrB, cleanupB := allocAndWriteRX(t, regionB)
	defer cleanupB()

	mask := New(
		Region{Addr: addrA, Size: uintptr(len(regionA))},
		Region{Addr: addrB, Size: uintptr(len(regionB))},
	)

	// Mid-sleep sampling: both markers should vanish from executable pages.
	var hitA, hitB atomic.Bool
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, a := testutil.ScanProcessMemory(regionA)
		_, b := testutil.ScanProcessMemory(regionB)
		hitA.Store(a)
		hitB.Store(b)
	}()

	mask.Sleep(context.Background(), 200 * time.Millisecond)

	assert.False(t, hitA.Load(), "region A marker must be hidden mid-sleep")
	assert.False(t, hitB.Load(), "region B marker must be hidden mid-sleep")

	// Byte-level restoration.
	gotA := unsafe.Slice((*byte)(unsafe.Pointer(addrA)), len(regionA))
	gotB := unsafe.Slice((*byte)(unsafe.Pointer(addrB)), len(regionB))
	assert.Equal(t, regionA, []byte(gotA), "region A bytes must be restored")
	assert.Equal(t, regionB, []byte(gotB), "region B bytes must be restored")
}

// TestSleepMaskE2E_BeaconLoopStableAcrossCycles simulates a beacon loop
// running 10 sleep cycles back-to-back. The bytes and protection of the
// protected region must be identical after every cycle.
func TestSleepMaskE2E_BeaconLoopStableAcrossCycles(t *testing.T) {
	const cycles = 10
	payload := testutil.WindowsSearchableCanary

	addr, cleanup := allocAndWriteRX(t, payload)
	defer cleanup()
	origProtect := queryProtect(t, addr)

	mask := New(Region{Addr: addr, Size: uintptr(len(payload))})

	for i := 0; i < cycles; i++ {
		mask.Sleep(context.Background(), 15 * time.Millisecond)

		got := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
		assert.Equal(t, payload, []byte(got), "cycle %d: payload bytes drifted", i)
		assert.Equal(t, origProtect, queryProtect(t, addr),
			"cycle %d: page protection drifted (want 0x%X)", i, origProtect)
	}
}

// TestSleepMaskE2E_BusyTrigAlsoDefeatsScanner confirms the BusyTrig
// (CPU-burn) sleep method gives the same memory-hiding guarantees as the
// default NtDelay method — the two differ in how they wait, not in how
// they protect memory.
func TestSleepMaskE2E_BusyTrigAlsoDefeatsScanner(t *testing.T) {
	payload := testutil.WindowsSearchableCanary
	addr, cleanup := allocAndWriteRX(t, payload)
	defer cleanup()

	marker := []byte("MALDEV_CANARY!!\n")
	_, ok := testutil.ScanProcessMemory(marker)
	require.True(t, ok, "baseline scan must find canary before masking")

	mask := New(Region{Addr: addr, Size: uintptr(len(payload))}).WithStrategy(&InlineStrategy{UseBusyTrig: true})

	var midHit atomic.Bool
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, hit := testutil.ScanProcessMemory(marker)
		midHit.Store(hit)
	}()

	mask.Sleep(context.Background(), 150 * time.Millisecond)

	assert.False(t, midHit.Load(), "BusyTrig sleep must also hide canary during the wait")

	_, ok = testutil.ScanProcessMemory(marker)
	assert.True(t, ok, "canary must be findable again after BusyTrig sleep")
}
