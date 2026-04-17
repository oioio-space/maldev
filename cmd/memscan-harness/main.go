// Command memscan-harness is the target-side companion for the
// vm-test-memscan orchestrator. It applies an evasion technique (SSN
// resolve, AMSI patch, ETW patch, or ntdll unhook) using one of the four
// syscall caller methods (WinAPI, NativeAPI, Direct, Indirect), prints a
// single READY line with relevant addresses, and sleeps until killed.
//
// Flags:
//
//	-group     ssn | amsi | etw | unhook    (required)
//	-caller    winapi | nativeapi | direct | indirect      (default winapi)
//	-resolver  hellsgate | halosgate | tartarus | hashgate (SSN group only)
//	-fn        ntdll function name (SSN group only)
//	-variant   classic | full (unhook group only)
//
// Windows-only.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	group := flag.String("group", "", "verification group: ssn|amsi|etw|unhook|inject")
	caller := flag.String("caller", "winapi", "syscall caller: winapi|nativeapi|direct|indirect")
	resolver := flag.String("resolver", "hellsgate", "SSN resolver: hellsgate|halosgate|tartarus|hashgate")
	fn := flag.String("fn", "NtAllocateVirtualMemory", "ntdll function (SSN group)")
	variant := flag.String("variant", "classic", "unhook variant: classic|full")
	method := flag.String("method", "ct", "inject method: ct|crt|apc|earlybird|etwthr|apcex|sectionmap|threadpool")
	flag.Parse()
	if *group == "" {
		fmt.Fprintln(os.Stderr, "memscan-harness: -group required")
		os.Exit(2)
	}
	if err := run(*group, *caller, *resolver, *fn, *variant, *method); err != nil {
		fmt.Fprintf(os.Stderr, "memscan-harness: %v\n", err)
		os.Exit(1)
	}
}
