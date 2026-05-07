//go:build !amd64

package antivm

// SIDT returns 0/0 on non-amd64 — the SIDT instruction is x86 /
// amd64 only. Operators on arm64 / mips / s390x targets should
// fall back to [Detect] / [DetectAll] for the
// registry/file/NIC dimensions.
func SIDT() (base uint64, limit uint16) { return 0, 0 }

// SGDT returns 0/0 on non-amd64. See [SIDT] for rationale.
func SGDT() (base uint64, limit uint16) { return 0, 0 }

// SLDT returns 0 on non-amd64. See [SIDT] for rationale.
func SLDT() uint16 { return 0 }

// redpillProbe returns a zero-valued report on non-amd64 — every
// underlying primitive is unavailable so [RedpillReport.LikelyVM]
// is always false.
func redpillProbe() RedpillReport { return RedpillReport{} }
