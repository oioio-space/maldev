package samdump

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Account is one user record decrypted from the SAM hive. RID is the
// account's relative identifier (numeric component of the SID); LM
// and NT are the 16-byte hash bytes (nil when the corresponding hash
// type is empty in the database). Username is decoded from the V
// value's UTF-16 username region.
//
// Pwdump renders Account as the canonical secretsdump line:
//
//	username:RID:LM_HEX:NT_HEX:::
//
// Tooling that consumes pwdump (hashcat -m 1000, John --format=NT,
// CrackMapExec NTLM hash auth) accepts this layout directly.
type Account struct {
	Username string
	RID      uint32
	LM       []byte
	NT       []byte
}

// Pwdump returns the canonical pwdump line for a, with empty/missing
// hashes rendered as the all-zeros (LM/NT inactive) sentinel. The
// trailing ":::" is part of the spec.
func (a Account) Pwdump() string {
	const inactive = "00000000000000000000000000000000"
	lm := inactive
	nt := inactive
	if len(a.LM) == 16 {
		lm = hex.EncodeToString(a.LM)
	}
	if len(a.NT) == 16 {
		nt = hex.EncodeToString(a.NT)
	}
	return fmt.Sprintf("%s:%d:%s:%s:::", a.Username, a.RID, lm, nt)
}

// ErrNotImplemented marks features still under construction. The
// chantier-VII commit train fills these in:
//
//   v0.0.1 — hive parser + sentinel errors (this commit).
//   v0.0.2 — syskey extractor (JD/Skew1/GBG/Data permutation).
//   v0.0.3 — LSA key extractor (Policy\\PolEKList AES-256 unwrap).
//   v0.0.4 — domain-key derivation + per-RID NT/LM unwrap.
//   v0.0.5 — Dump end-to-end + intrusive Win VM smoke test.
//   v0.1.0 — Live mode via recon/shadowcopy.
var ErrNotImplemented = errors.New("samdump: feature not yet implemented (chantier VII in progress)")

// Dump returns the per-user credentials in the SAM hive at samHive,
// using the SYSTEM hive at systemHive to recover the boot key + LSA
// key + per-domain hashed bootkey. Both readers must support
// concurrent ReadAt for the entire hive bytes; samdump loads each
// hive into memory once.
//
// Currently a scaffold — returns ErrNotImplemented. The chantier-VII
// commit train (v0.0.2 → v0.1.0) wires the algorithm in slices.
func Dump(systemHive io.ReaderAt, systemSize int64, samHive io.ReaderAt, samSize int64) ([]Account, error) {
	if _, err := readHive(systemHive, systemSize); err != nil {
		return nil, fmt.Errorf("read SYSTEM hive: %w", err)
	}
	if _, err := readHive(samHive, samSize); err != nil {
		return nil, fmt.Errorf("read SAM hive: %w", err)
	}
	return nil, ErrNotImplemented
}
