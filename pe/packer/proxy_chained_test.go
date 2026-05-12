package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/dllproxy"
	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestPackChainedProxyDLL_HappyPath proves the two-file
// orchestration produces (a) a valid PE32+ DLL with the right
// IMAGE_FILE_DLL bit + ImportTable referencing the payload name,
// and (b) a valid PE32+ DLL marked as the converted-DLL output.
func TestPackChainedProxyDLL_HappyPath(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	proxy, payload, _, err := packer.PackChainedProxyDLL(exe, packer.ChainedProxyDLLOptions{
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
			Seed:         42,
		},
	})
	if err != nil {
		t.Fatalf("PackChainedProxyDLL: %v", err)
	}
	if len(proxy) == 0 || len(payload) == 0 {
		t.Fatalf("empty output: proxy=%d payload=%d", len(proxy), len(payload))
	}

	// Proxy must parse + carry IMAGE_FILE_DLL + reference payload.dll.
	pf, err := pe.NewFile(bytes.NewReader(proxy))
	if err != nil {
		t.Fatalf("debug/pe rejected proxy: %v", err)
	}
	defer pf.Close()
	if pf.Characteristics&transform.ImageFileDLL == 0 {
		t.Errorf("proxy Characteristics = 0x%x, missing IMAGE_FILE_DLL", pf.Characteristics)
	}
	if !bytes.Contains(proxy, []byte("payload.dll")) {
		t.Error("proxy doesn't embed PayloadDLL string 'payload.dll'")
	}
	if !bytes.Contains(proxy, []byte("LoadLibraryA")) {
		t.Error("proxy doesn't import LoadLibraryA")
	}

	// Payload must parse + carry IMAGE_FILE_DLL.
	pp, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("debug/pe rejected payload: %v", err)
	}
	defer pp.Close()
	if pp.Characteristics&transform.ImageFileDLL == 0 {
		t.Errorf("payload Characteristics = 0x%x, missing IMAGE_FILE_DLL", pp.Characteristics)
	}
}

// TestPackChainedProxyDLL_RejectsEmptyTarget validates input
// validation surfaces a clear error rather than failing deeper.
func TestPackChainedProxyDLL_RejectsEmptyTarget(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, _, err := packer.PackChainedProxyDLL(exe, packer.ChainedProxyDLLOptions{
		Exports: []dllproxy.Export{{Name: "x"}},
	})
	if err == nil || !contains(err.Error(), "TargetName required") {
		t.Errorf("got %v, want 'TargetName required'", err)
	}
}

// TestPackChainedProxyDLL_RejectsEmptyExports — same admission
// guard for Exports.
func TestPackChainedProxyDLL_RejectsEmptyExports(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	_, _, _, err := packer.PackChainedProxyDLL(exe, packer.ChainedProxyDLLOptions{
		TargetName: "version",
	})
	if err == nil || !contains(err.Error(), "Exports required") {
		t.Errorf("got %v, want 'Exports required'", err)
	}
}

// TestPackChainedProxyDLL_DefaultsPayloadName confirms the
// "payload.dll" default fires when PayloadDLLName is empty.
func TestPackChainedProxyDLL_DefaultsPayloadName(t *testing.T) {
	exe, _ := transform.BuildMinimalPE32Plus([]byte{0xC3})
	proxy, _, _, err := packer.PackChainedProxyDLL(exe, packer.ChainedProxyDLLOptions{
		TargetName: "version",
		Exports:    []dllproxy.Export{{Name: "x"}},
	})
	if err != nil {
		t.Fatalf("PackChainedProxyDLL: %v", err)
	}
	if !bytes.Contains(proxy, []byte("payload.dll")) {
		t.Error("default 'payload.dll' name not embedded in proxy")
	}
}

// contains is strings.Contains with a shorter call site for
// error-message assertions.
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// Used only to keep the errors import live for future test
// extensions that assert specific sentinel types.
var _ = errors.New
