//go:build windows

// Package com holds Windows COM helpers shared across maldev.
//
// Currently exposes a single [Error] helper that wraps a non-zero
// HRESULT into a contextualised Go error. Used by the COM-heavy
// packages [github.com/oioio-space/maldev/persistence/lnk] and
// [github.com/oioio-space/maldev/runtime/clr].
package com

import "fmt"

// Error returns nil if hr is S_OK (0), otherwise a wrapped error
// formatted as `"<stage>: HRESULT 0x<8-hex>"`. The stage string
// should name the COM call site for fast triage in logs.
func Error(stage string, hr uintptr) error {
	if hr == 0 {
		return nil
	}
	return fmt.Errorf("%s: HRESULT 0x%08x", stage, uint32(hr))
}
