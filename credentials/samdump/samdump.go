package samdump

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
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

// ErrDump is returned when Dump can't complete — bad hive, missing
// boot/domain key, no users found, or a per-user decrypt step fails.
// Per-user warnings are accumulated on Result.Warnings rather than
// aborting the whole dump.
var ErrDump = errors.New("samdump: dump failed")

// Result aggregates the output of a successful Dump. Accounts is the
// per-user credentials list. Warnings carries non-fatal anomalies
// (single-user parse failures, missing optional fields) so the
// operator can audit incomplete dumps without losing the rest.
type Result struct {
	Accounts []Account
	Warnings []string
}

// Pwdump renders r as a multi-line pwdump file (one Account per
// line). Sorted by RID for stable output.
func (r Result) Pwdump() string {
	var sb strings.Builder
	for i := range r.Accounts {
		sb.WriteString(r.Accounts[i].Pwdump())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Dump returns the per-user credentials in the SAM hive at samHive,
// using the SYSTEM hive at systemHive to recover the boot key and
// per-domain hashed bootkey. Both readers must support ReadAt over
// the entire hive bytes; samdump loads each hive into memory once.
//
// Algorithm:
//
//   1. SYSTEM hive → extract 16-byte boot key (extractBootKey).
//   2. SAM hive → read SAM\Domains\Account\F → derive domain hashed
//      bootkey (deriveDomainKey, AES or legacy by revision tag).
//   3. SAM hive → enumerate SAM\Domains\Account\Users\<RID>
//      subkeys, parse each user's V value (parseUserV) and decrypt
//      the NT + LM hash blobs (decryptUserNT / decryptUserLM).
//
// Per-user failures collect on Result.Warnings; only structural
// failures (missing boot key, malformed F value, no Users key)
// abort with ErrDump.
func Dump(systemHive io.ReaderAt, systemSize int64, samHive io.ReaderAt, samSize int64) (Result, error) {
	system, err := readHive(systemHive, systemSize)
	if err != nil {
		return Result{}, errors.Join(ErrDump, fmt.Errorf("read SYSTEM hive: %w", err))
	}
	sam, err := readHive(samHive, samSize)
	if err != nil {
		return Result{}, errors.Join(ErrDump, fmt.Errorf("read SAM hive: %w", err))
	}

	bootkey, err := extractBootKey(system)
	if err != nil {
		return Result{}, errors.Join(ErrDump, err)
	}

	fValue, err := readDomainAccountF(sam)
	if err != nil {
		return Result{}, errors.Join(ErrDump, err)
	}
	hashedBootkey, err := deriveDomainKey(bootkey, fValue)
	if err != nil {
		return Result{}, errors.Join(ErrDump, err)
	}

	rids, err := listUserRIDs(sam)
	if err != nil {
		return Result{}, errors.Join(ErrDump, err)
	}
	res := Result{}
	for _, rid := range rids {
		v, err := readUserV(sam, rid)
		if err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d: read V: %v", rid, err))
			continue
		}
		parsed, err := parseUserV(v)
		if err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d: parse V: %v", rid, err))
			continue
		}
		acct := Account{
			Username: parsed.Username,
			RID:      rid,
		}
		if nt, err := decryptUserNT(hashedBootkey, rid, parsed.NTHashEnc); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d (%s): NT decrypt: %v", rid, parsed.Username, err))
		} else {
			acct.NT = nt
		}
		if lm, err := decryptUserLM(hashedBootkey, rid, parsed.LMHashEnc); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d (%s): LM decrypt: %v", rid, parsed.Username, err))
		} else {
			acct.LM = lm
		}
		res.Accounts = append(res.Accounts, acct)
	}
	return res, nil
}
