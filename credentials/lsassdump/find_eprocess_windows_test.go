//go:build windows

package lsassdump

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestWalkProcessChain_FindsTargetPID builds a 3-process synthetic
// kernel chain (System → svchost → lsass) and verifies the walker
// returns the right EPROCESS VA when probed for lsass's PID.
//
// Layout per process: a 0x500-byte region with UniqueProcessId at
// upidOff, ActiveProcessLinks (Flink+Blink) at apLinksOff. The
// Flink chain wraps back to System (head) so the loop terminates
// cleanly.
func TestWalkProcessChain_FindsTargetPID(t *testing.T) {
	const (
		upidOff    uint32  = 0x440 // matches Win 10 22H2
		apLinksOff uint32  = 0x448
		regionSize uintptr = 0x500

		systemVA  uintptr = 0xFFFFC0010A1B0000
		svchostVA uintptr = 0xFFFFC0010A1B0500
		lsassVA   uintptr = 0xFFFFC0010A1B0A00

		systemPID  uint32 = 4
		svchostPID uint32 = 1234
		lsassPID   uint32 = 644
	)

	mkProc := func(pid uint32, nextEP uintptr) []byte {
		buf := make([]byte, regionSize)
		// UniqueProcessId is a HANDLE (8 bytes); low 32 = PID.
		binary.LittleEndian.PutUint64(buf[upidOff:upidOff+8], uint64(pid))
		// ActiveProcessLinks.Flink: address of next.ActiveProcessLinks
		// (= nextEP + apLinksOff).
		binary.LittleEndian.PutUint64(buf[apLinksOff:apLinksOff+8],
			uint64(nextEP+uintptr(apLinksOff)))
		return buf
	}

	rw := newPPLMockRW(map[uintptr][]byte{
		systemVA:  mkProc(systemPID, svchostVA),
		svchostVA: mkProc(svchostPID, lsassVA),
		lsassVA:   mkProc(lsassPID, systemVA), // wraps back to head
	})

	got, err := walkProcessChain(rw, systemVA, upidOff, apLinksOff, lsassPID)
	if err != nil {
		t.Fatalf("walkProcessChain: %v", err)
	}
	if got != lsassVA {
		t.Errorf("EPROCESS = 0x%X, want 0x%X", got, lsassVA)
	}
}

// TestWalkProcessChain_HeadMatch — when the head's PID matches,
// the walker returns the head VA without traversing further.
func TestWalkProcessChain_HeadMatch(t *testing.T) {
	const (
		upidOff    uint32  = 0x440
		apLinksOff uint32  = 0x448
		regionSize uintptr = 0x500
		systemVA   uintptr = 0xFFFFC0010A1B0000
	)

	buf := make([]byte, regionSize)
	binary.LittleEndian.PutUint64(buf[upidOff:upidOff+8], 4) // System PID
	rw := newPPLMockRW(map[uintptr][]byte{systemVA: buf})

	got, err := walkProcessChain(rw, systemVA, upidOff, apLinksOff, 4)
	if err != nil {
		t.Fatalf("walkProcessChain: %v", err)
	}
	if got != systemVA {
		t.Errorf("EPROCESS = 0x%X, want 0x%X", got, systemVA)
	}
}

// TestWalkProcessChain_NotFound — the walker returns the sentinel
// when no node matches the requested PID before the loop wraps.
func TestWalkProcessChain_NotFound(t *testing.T) {
	const (
		upidOff    uint32  = 0x440
		apLinksOff uint32  = 0x448
		regionSize uintptr = 0x500
		systemVA   uintptr = 0xFFFFC0010A1B0000
		svchostVA  uintptr = 0xFFFFC0010A1B0500
	)

	mkProc := func(pid uint32, nextEP uintptr) []byte {
		b := make([]byte, regionSize)
		binary.LittleEndian.PutUint64(b[upidOff:upidOff+8], uint64(pid))
		binary.LittleEndian.PutUint64(b[apLinksOff:apLinksOff+8],
			uint64(nextEP+uintptr(apLinksOff)))
		return b
	}

	rw := newPPLMockRW(map[uintptr][]byte{
		systemVA:  mkProc(4, svchostVA),
		svchostVA: mkProc(1234, systemVA), // wraps
	})

	_, err := walkProcessChain(rw, systemVA, upidOff, apLinksOff, 9999)
	if !errors.Is(err, ErrLsassEProcessNotFound) {
		t.Errorf("err = %v, want ErrLsassEProcessNotFound", err)
	}
}

// TestWalkProcessChain_NilFlinkBreaks — if a node's Flink reads
// as zero (corrupted), the walker stops cleanly rather than
// chasing into address 0.
func TestWalkProcessChain_NilFlinkBreaks(t *testing.T) {
	const (
		upidOff    uint32  = 0x440
		apLinksOff uint32  = 0x448
		regionSize uintptr = 0x500
		systemVA   uintptr = 0xFFFFC0010A1B0000
	)

	buf := make([]byte, regionSize)
	binary.LittleEndian.PutUint64(buf[upidOff:upidOff+8], 4) // PID 4 (head)
	// Flink stays zero by default → walker breaks out.
	rw := newPPLMockRW(map[uintptr][]byte{systemVA: buf})

	_, err := walkProcessChain(rw, systemVA, upidOff, apLinksOff, 9999)
	if !errors.Is(err, ErrLsassEProcessNotFound) {
		t.Errorf("err = %v, want ErrLsassEProcessNotFound", err)
	}
}

// TestFindLsassEProcess_NilReadWriter — guard.
func TestFindLsassEProcess_NilReadWriter(t *testing.T) {
	if _, err := FindLsassEProcess(nil, 644); err == nil {
		t.Fatal("err = nil, want ErrNotLoaded")
	}
}

// TestFindLsassEProcess_ZeroPID — guard.
func TestFindLsassEProcess_ZeroPID(t *testing.T) {
	rw := newPPLMockRW(nil)
	if _, err := FindLsassEProcess(rw, 0); err == nil {
		t.Fatal("err = nil, want PID == 0 error")
	}
}
