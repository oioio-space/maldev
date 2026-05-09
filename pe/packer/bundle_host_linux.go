//go:build amd64 && linux

package packer

// hostWinBuild always returns 0 on Linux — there is no PEB, and Windows
// build-number predicates do not apply. Bundles that target Linux
// should leave PT_WIN_BUILD unset on every entry.
func hostWinBuild() uint32 { return 0 }
