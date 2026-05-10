package packer

// Test-only re-exports for diagnostic harness paths in
// bundle_stub_winwrap_asmtrace_windows_test.go (which lives in the
// _test package and therefore can't see unexported symbols).
//
// These wrappers are gated to *_test.go files only — the build
// system never includes them in production binaries because their
// filename ends in _test.go.

// BundleStubVendorAwareWindowsForTest re-exports
// [bundleStubVendorAwareWindows] so external test code can extract
// the raw scan-stub bytes for asmtrace-harness routing.
func BundleStubVendorAwareWindowsForTest() ([]byte, error) {
	return bundleStubVendorAwareWindows()
}

// BundleOffsetImm32PosForTest re-exports the patchable imm32
// position constant.
const BundleOffsetImm32PosForTest = bundleOffsetImm32Pos
