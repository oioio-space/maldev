// Package donors lists the reference (donor) PE files the
// pe/masquerade preset generator and the cmd/cert-snapshot tool
// share. Single source of truth so adding a new identity in one
// place flows through both pipelines (cosmetic .syso bundling +
// Authenticode cert blob extraction).
//
// The package also bundles pre-extracted WIN_CERTIFICATE blobs
// for every donor whose Authenticode signature is embedded in
// the PE itself — operators graft offline via [LoadBlob] without
// needing the donor on disk:
//
//	raw, _ := donors.LoadBlob("claude")
//	cert.Write("implant.exe", &cert.Certificate{Raw: raw})
//
// Operators with custom build pipelines can iterate [All]
// directly to drive their own per-identity tooling. The [Donor]
// struct shape is stable; the slice contents grow as new donors
// land.
//
// Paths use OS env-vars (${SystemRoot}, ${ProgramFiles},
// ${LOCALAPPDATA}) — callers expand via os.ExpandEnv before
// touching disk.
//
// # MITRE ATT&CK
//
//   - T1036.005 (Match Legitimate Name or Location) — donor list
//     drives the masquerade pipeline; bundled cert blobs feed
//     T1553.002 (Subvert Trust Controls: Code Signing).
//
// # Detection level
//
// very-quiet
//
// Pure data + offline file I/O via embed.FS. No syscalls, no
// network, no runtime artefacts. The bundled blobs ARE published
// research artefacts and may be fingerprinted by threat-intel
// crawlers — see "Limitations" in docs/techniques/pe/certificate-theft.md.
//
// # Required privileges
//
// unprivileged. embed.FS reads are pure-Go in-process; no
// disk access from this package's code path.
//
// # Platform
//
// Cross-platform. The donor PATHS are Windows-shaped (env-var
// expansion happens at consumer sites — gen, cert-snapshot —
// which gate on //go:build windows themselves). The blob data
// and listing helpers run on any host the Go toolchain supports.
//
// # See also
//
//   - docs/techniques/pe/certificate-theft.md — operator workflow
//   - docs/techniques/pe/masquerade.md — preset side
//   - [github.com/oioio-space/maldev/pe/cert] — Write / Copy / Read
package donors
