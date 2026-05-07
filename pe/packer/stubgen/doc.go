// Package stubgen orchestrates Phase 1e-A's per-pack stub generation.
// Generate() takes the inner blob (stage 2 || encrypted payload || key)
// plus configuration and produces a complete runnable Windows PE32+ that,
// when executed, peels the polymorphic SGN encoding and JMPs into the
// embedded stage 2.
//
// Pipeline at a glance:
//
//	encoded, rounds := poly.Engine.EncodePayload(inner)
//	for i = N-1 .. 0:
//	    stage1.Emit(builder, rounds[i], "loop_i", "payload", len(encoded))
//	stage1Bytes = builder.Encode()
//	host.EmitPE(stage1Bytes, encoded) → final PE
//
// Self-test: before returning, the package re-applies the rounds in
// reverse via a Go reference decoder; if the recovered bytes don't match
// the original inner, ErrEncodingSelfTestFailed fires.
//
// # Detection level
//
// N/A — pack-time only. No technique-specific detection concern: the
// output PE's detection surface belongs to the caller's payload, not
// to this package.
//
// # MITRE ATT&CK
//
// T1027.002 — Obfuscated Files or Information: Software Packing.
package stubgen
