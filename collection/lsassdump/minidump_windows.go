//go:build windows

package lsassdump

// MiniDump stream writer — filled in by C1.2 of the v0.15.0 plan.
//
// Layout target (Microsoft's MINIDUMP_HEADER + Directory):
//
//   [MINIDUMP_HEADER]
//   [MINIDUMP_DIRECTORY × NumberOfStreams]
//   [streams: SystemInfoStream, ModuleListStream, ThreadListStream,
//            HandleDataStream, Memory64ListStream]
//   [raw memory blobs pointed at by Memory64ListStream]
//
// Reference: winnt.h MINIDUMP_* structs and minidumpapiset.h.
//
// Everything here is pure-Go struct packing — no call into
// MiniDumpWriteDump (heavily EDR-hooked).
