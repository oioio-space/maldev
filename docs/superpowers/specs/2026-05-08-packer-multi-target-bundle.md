---
last_reviewed: 2026-05-08
status: draft
reflects_commit: 082dde9
---

# C6 — Multi-Target Bundle: Wire Format, Fingerprint Predicates, and Stub Flow

> Spec for the post-v0.66 packer chantier. Covers bundle wire format,
> CPUID/build-number fingerprint predicates, stub flow extensions, threat
> model, API sketch, and open questions. This is a SPEC, not an
> implementation. Implementation is queued for the next major chantier
> window after C3 lands.

---

## 1. Goal

Pack N independent payloads (one per target environment) into a single
binary. At runtime the stub fingerprints the host — querying the CPU vendor
string and the OS build number from in-memory kernel structures — selects
the matching payload, decrypts it, and JMPs to the original entry point. All
non-matching payloads remain encrypted on disk and in memory throughout the
process lifetime. A defender who captures the on-disk binary sees N
indistinguishable encrypted blobs; without running the binary on the exact
target configuration, they cannot determine which blob is "the real
payload".

---

## 2. Operator Scenario

An operator needs to deliver a payload against three known targets: a legacy
Windows 10 21H2 system with an AMD CPU, a Windows 11 23H2 system with an
Intel CPU, and a Windows Server 2022 LTSC system of any vendor. The operator
builds three separate payload EXEs (each tuned for its target), then runs
`PackBinaryBundle` once. The output is a single EXE. When the target
executes it, the stub reads `CPUID EAX=0` to obtain the vendor string
(`"AuthenticAMD"`, `"GenuineIntel"`, or a wildcard), then reads
`RtlGetVersion` data from the PEB's `OsVersionInfo` fields to check the
build number (19041 for W10 21H2, 22631 for W11 23H2, 20348 for Server
2022). The stub picks the matching payload, XOR-decodes it in place, and
JMPs to the OEP. The other two encrypted blobs are never touched. If
analysts at a sandbox analyse the binary on a different OS build, they see
only an encrypted blob, an empty decryption result, and a clean exit — no
shellcode surfaces.

---

## 3. Bundle Wire Format

All multi-byte integers are little-endian. The bundle is a self-contained
flat binary. Its entry point (via the PE32+ `AddressOfEntryPoint` or ELF
`e_entry`) points directly into the bundle header.

### 3.1 Top-level layout

```
[BundleHeader]
[FingerprintEntry × count]
[PayloadEntry × count]
[EncryptedPayloadData × count]   (variable-length, in payload order)
```

All four regions are contiguous in file and virtual address space; no
padding or alignment gaps between regions except where noted.

### 3.2 BundleHeader (32 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic | `0x4D4C4456` (`"MLDV"`) |
| 4 | 2 | Version | Format version, currently `0x0001` |
| 6 | 2 | Count | Number of payloads N (1..255) |
| 8 | 4 | FpTableOffset | RVA of first FingerprintEntry from bundle start |
| 12 | 4 | PayloadTableOffset | RVA of first PayloadEntry from bundle start |
| 16 | 4 | DataOffset | RVA of first EncryptedPayloadData byte |
| 20 | 4 | FallbackBehaviour | 0=silent exit, 1=loud crash, 2=first-payload |
| 24 | 8 | Reserved | Must be zero |

### 3.3 FingerprintEntry (48 bytes per entry)

One entry per payload, in same order as the PayloadEntry array.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | PredicateType | See §3.4 |
| 1 | 1 | Flags | Bit 0: NEGATE (match if predicate false) |
| 2 | 2 | Reserved | Must be zero |
| 4 | 12 | VendorString | CPUID vendor (12 ASCII bytes, NUL-padded). Ignored unless PredicateType & CPUID_VENDOR. All zeros = wildcard (match any). |
| 16 | 4 | BuildMin | Minimum Windows build number (inclusive). 0 = no lower bound. |
| 20 | 4 | BuildMax | Maximum Windows build number (inclusive). 0 = no upper bound. |
| 24 | 4 | AndMask | CPUID ECX feature mask (checked against `CPUID EAX=1`). 0 = skip. |
| 28 | 4 | AndValue | Required value for `(ECX & AndMask) == AndValue`. |
| 32 | 16 | Reserved2 | Must be zero; reserved for future predicate types |

**PredicateType flags** (bitfield, combinable):

| Bit | Name | Check performed |
|-----|------|----------------|
| 0 | `PT_CPUID_VENDOR` | 12-byte vendor string from `CPUID EAX=0x40000000`: EBX+ECX+EDX |
| 1 | `PT_WIN_BUILD` | PEB walk for `NtMajorVersion/NtMinorVersion/BuildNumber` fields |
| 2 | `PT_CPUID_FEATURES` | `CPUID EAX=1` ECX feature mask |
| 3 | `PT_MATCH_ALL` | Always matches (default/wildcard payload) |

Predicates at bits 0–2 are ANDed together: all enabled checks must pass.
Bit 3 overrides all others. The stub evaluates FingerprintEntries in order
0..N-1 and selects the first matching entry.

### 3.4 PayloadEntry (32 bytes per entry)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | DataRVA | RVA of this payload's encrypted bytes from bundle start |
| 4 | 4 | DataSize | Size in bytes of the encrypted payload (on disk) |
| 8 | 4 | PlaintextSize | Original size before encryption |
| 12 | 1 | CipherType | 0=XOR-byte, 1=XOR-rolling, 2=reserved |
| 13 | 3 | Reserved | Must be zero |
| 16 | 16 | Key | Per-payload encryption key (16 bytes, zero-extended for shorter keys) |

### 3.5 EncryptedPayloadData

The variable-length payload blobs, concatenated in entry order. Each blob's
file offset is `DataRVA` (relative to bundle header). Blobs need not be
contiguous (a packer revision may add alignment), but in v1 they are packed
directly, 1-byte aligned.

---

## 4. Fingerprint Predicate Types

### 4.1 CPUID Vendor String (PT_CPUID_VENDOR)

AMD64 processors expose a 12-byte vendor identification string via `CPUID`
with `EAX=0`. The return registers `EBX`, `ECX`, `EDX` (in that order)
contain the string as four-byte little-endian chunks. Known values:

| Vendor | String |
|--------|--------|
| Intel | `"GenuineIntel"` |
| AMD | `"AuthenticAMD"` |
| Hyper-V (Microsoft) | `"Microsoft Hv"` |
| VMware | `"VMwareVMware"` |
| VirtualBox | `"VBoxVBoxVBox"` |
| KVM | `"KVMKVMKVM\0\0\0"` |

The stub emits the CPUID instruction directly via `0x0F 0xA2` (no OS call),
reads the three registers, and compares against `FingerprintEntry.VendorString`.
All-zero `VendorString` skips this check (wildcard).

The `0x40000000` leaf (hypervisor vendor) is also useful for sandbox
detection: `"Microsoft Hv"` indicates Hyper-V (common in automated
sandboxes); the stub can use this to skip payload execution.

### 4.2 Windows Build Number (PT_WIN_BUILD)

The Windows NT build number is available from the Process Environment Block
(PEB) without calling any API. The PEB is accessible via the GS segment
register:

```
; Read PEB pointer (Windows x64)
mov rax, gs:[0x60]      ; RAX = PEB*

; Read OSVERSIONINFOEXW fields from PEB
; PEB.OSMajorVersion at offset 0x118 (Win10+)
movzx ecx, word ptr [rax + 0x120]   ; BuildNumber (WORD at PEB+0x120)
```

The exact offsets are:
- `PEB + 0x118` = `ULONG OSMajorVersion`
- `PEB + 0x11C` = `ULONG OSMinorVersion`
- `PEB + 0x120` = `ULONG OSBuildNumber`

These offsets are stable across Windows 7 through Windows 11 and Server
2022 (confirmed from public WinDbg dumps and ReactOS source). The stub
reads only `OSBuildNumber` (4 bytes) and checks it against `[BuildMin,
BuildMax]`.

Reference build numbers:

| OS | Build |
|----|-------|
| Windows 7 | 7601 |
| Windows 8.1 | 9600 |
| Windows 10 1507 | 10240 |
| Windows 10 21H2 | 19041 |
| Windows 11 22H2 | 22621 |
| Windows 11 23H2 | 22631 |
| Windows Server 2022 | 20348 |
| Windows Server 2019 | 17763 |

### 4.3 Predicate Combinations (AND logic)

Within a single FingerprintEntry, enabled predicate bits are ANDed: the
entry matches only if ALL enabled checks pass. To express OR logic (e.g.,
"AMD on any Windows 10 build OR Intel on Windows 11"), the operator creates
two separate FingerprintEntry records pointing to the same (or distinct)
payload.

Example: Intel + Windows 11 OR AMD + Windows 10, each running a different
payload:

```go
entries := []BundleFingerprint{
    {
        PredicateType: PT_CPUID_VENDOR | PT_WIN_BUILD,
        VendorString:  "GenuineIntel",
        BuildMin: 22000, BuildMax: 99999,
    },
    {
        PredicateType: PT_CPUID_VENDOR | PT_WIN_BUILD,
        VendorString:  "AuthenticAMD",
        BuildMin: 10000, BuildMax: 21999,
    },
}
```

---

## 5. Stub Flow

The bundle stub extends the existing polymorphic SGN stub with a
fingerprint-evaluator prefix that runs before the CALL+POP+ADD prologue.

```mermaid
flowchart TD
    A[EXE Entry: bundle stub starts] --> B[Read CPUID vendor EAX=0]
    B --> C[Read PEB.OSBuildNumber via GS:0x60]
    C --> D{FingerprintEntry[i] matches?}
    D -- No, i < N --> E[i++]
    E --> D
    D -- No match after all N --> F{FallbackBehaviour}
    F -- exit --> G[RET / ExitProcess]
    F -- first --> H[i = 0]
    H --> I
    D -- Yes --> I[Load PayloadEntry[i]: DataRVA, DataSize, Key]
    I --> J[XOR-decrypt payload in place at DataRVA]
    J --> K[CALL+POP+ADD prologue: R15 = payload base]
    K --> L[SGN decoder rounds over payload]
    L --> M[JMP to payload OEP]
```

The fingerprint evaluator is pure asm, emitted as raw bytes before the
existing SGN prologue. Its register contract: all callee-saved registers
(R12–R15, RBX, RSP) are preserved entering and exiting the evaluator; R8,
R9, R10, R11, RAX, RCX, RDX, RSI, RDI are scratch. The evaluator uses only
scratch registers so the existing SGN decoder rounds are unaffected.

The payload selector and decryptor are also asm: they read the PayloadEntry
via R15-relative addressing (R15 is loaded with the bundle header RVA from
the same CALL+POP+ADD prologue), compute the payload data pointer, and loop
over `DataSize` bytes XORing with the key. The SGN decoder then runs over
the decrypted payload, followed by a JMP to OEP.

---

## 6. Threat Model

### 6.1 What defenders see

On-disk: N encrypted blobs separated by a small header and a fingerprint
table. The fingerprint table is plaintext (it must be for the stub to
evaluate it without decryption), but the predicate values reveal only
environmental constraints — not the payload contents or OEP.

Dynamic analysis in a sandbox: The sandbox executes the binary on a fixed
environment (specific OS, specific CPU vendor, often Hyper-V). If the
sandbox environment does not match ANY fingerprint predicate, the stub
reaches `FallbackBehaviour = exit` and terminates cleanly. The sandbox
records a short-lived process that exited 0, with no network activity, no
heap allocations, and no code execution past the stub. No payload surfaces.

### 6.2 What this does NOT protect against

- **Forced execution**: A skilled analyst can patch `FingerprintEntry[0]`
  to `PT_MATCH_ALL` and force decryption. The per-payload XOR key is stored
  in the `PayloadEntry` in plaintext — once the predicate is bypassed, the
  payload is trivially decryptable.
- **Emulation**: Modern sandboxes (Cuckoo, Any.Run) emulate CPUID and PEB
  values. An operator can use more exotic predicates (timing, hardware
  quirks) for stronger anti-sandbox, but those are outside this spec.
- **Signature of the stub itself**: The fingerprint evaluator + CPUID +
  PEB walk are recognisable sequences. Poly-engine junk insertion around
  the evaluator is a future hardening pass (C6-phase-2).

### 6.3 Blast-radius reduction

If one payload is extracted and analysed (e.g., the AMD variant),
signatures derived from it will NOT match the Intel variant (different
plaintext, independent key). This reduces the blast radius of a single
extraction: defenders cannot auto-pivot to the other variants without
obtaining and running the binary on the other target configurations.

---

## 7. API Sketch

```go
// BundlePayload is one payload binary paired with its target fingerprint.
type BundlePayload struct {
    Binary      []byte             // original PE/ELF binary
    Fingerprint FingerprintPredicate
    Options     PackBinaryOptions  // per-payload stub options (rounds, seed, etc.)
}

// FingerprintPredicate encodes the host-matching logic for one payload.
type FingerprintPredicate struct {
    // PredicateType is a bitmask of PT_* constants.
    PredicateType uint8

    // VendorString is the 12-byte CPUID vendor to match.
    // Empty/all-zero means wildcard (any vendor).
    VendorString [12]byte

    // BuildMin and BuildMax define an inclusive Windows build number range.
    // Zero means "no bound" in that direction.
    BuildMin uint32
    BuildMax uint32

    // CPUIDFeatureMask and CPUIDFeatureValue check (CPUID[1].ECX & mask) == value.
    CPUIDFeatureMask  uint32
    CPUIDFeatureValue uint32

    // Fallback, when true on a FingerprintPredicate, marks this payload as
    // the last-resort fallback when no other predicate matches. At most one
    // payload in a bundle may be the fallback.
    Fallback bool
}

// BundleOptions parameterizes PackBinaryBundle.
type BundleOptions struct {
    // FallbackBehaviour controls what happens when no predicate matches.
    // BundleFallbackExit (default) exits cleanly.
    // BundleFallbackFirst selects the first payload unconditionally.
    FallbackBehaviour BundleFallbackBehaviour
}

// PackBinaryBundle packs N payload binaries into a single multi-target
// bundle binary. The bundle selects the matching payload at runtime via
// CPUID + PEB fingerprinting and decrypts only the selected payload.
//
// Returns the packed bundle bytes. The caller is responsible for writing
// the bundle to a PE/ELF container (via InjectStubPE/InjectStubELF) and
// setting its entry point to the bundle stub's start.
//
// Error conditions:
//   - ErrEmptyBundle: payloads is nil or len(payloads) == 0.
//   - ErrBundleTooLarge: len(payloads) > 255.
//   - ErrMultipleFallbacks: more than one payload has Fallback=true.
//   - Any PackBinary error from the individual payload packing passes.
func PackBinaryBundle(payloads []BundlePayload, opts BundleOptions) ([]byte, error)
```

---

## 8. Implementation Phases

### Phase P1 — Single-target sanity (no selection logic)

**Goal:** Ship the wire format without the fingerprint evaluator. The bundle
header and PayloadEntry are serialised correctly; the stub decrypts payload 0
unconditionally and JMPs to OEP. This is a regression-safe baseline: the
existing multi-seed E2E tests pass with N=1 bundles.

**Files:**
- Create `pe/packer/bundle.go` — `PackBinaryBundle`, wire format serialiser,
  `BundlePayload`, `FingerprintPredicate`, `BundleOptions`.
- Create `pe/packer/bundle_test.go` — synthetic N=1 PE bundle, verify header
  magic, PayloadEntry, encrypted blob round-trips via `debug/pe`.
- Tag `v0.67.0-alpha.1`.

### Phase P2 — Fingerprint ASM emitter

**Goal:** Add CPUID + PEB walk asm as raw bytes, tested in isolation via
mmap'd pages (same pattern as `lz4_inflate_test.go`).

**Files:**
- Create `pe/packer/stubgen/stage1/fingerprint.go` —
  `EmitCPUIDVendorRead(b)`, `EmitPEBBuildRead(b)`.
- Create `pe/packer/stubgen/stage1/fingerprint_test.go` (Linux-only,
  mmap) — verify CPUID vendor bytes match Go's `cpu.x86` detection,
  verify PEB build number matches `windows.RtlGetVersion` on Windows VM.

### Phase P3 — Selection logic + evaluator loop

**Goal:** Emit the full fingerprint evaluator asm into the stub. The stub
iterates FingerprintEntries, checks predicates, breaks on first match, falls
through to the payload decryptor.

**Files:**
- Extend `pe/packer/stubgen/stage1/stub.go` with `EmitBundleEvaluator(b,
  bundleRVA, fingerprintTableRVA, payloadTableRVA, count)`.
- Update `stubgen.Generate` to accept bundle mode (new `BundleMode bool`
  flag in `Options`).
- New test `TestEmitBundleEvaluator_SelectsCorrectEntry` — two-entry bundle,
  assert correct payload is selected by comparing XOR output.

### Phase P4 — Multi-payload encryption + E2E

**Goal:** Each payload gets an independent random key. E2E: pack two
distinct hello-world binaries (x86-64 Linux), exec on two different machines
(or with patched PEB values), assert each produces distinct output.

**Files:**
- Extend `bundle.go` with `encryptPayload(plaintext []byte) (ciphertext, key []byte)`.
- E2E test `TestPackBinaryBundle_TwoPayloads_Linux` — synthetic two-entry
  bundle with AMD/Intel predicates, patch PEB stub to force each path,
  verify correct hello string.
- Tag `v0.67.0`.

---

## 9. Open Questions

| # | Question | Current leaning |
|---|----------|-----------------|
| Q1 | **No-match fallback: exit(0) or loud crash?** | Default `FallbackBehaviour = BundleFallbackExit` (exit clean, no crash). Operator opt-in `BundleFallbackFirst` for dev/test. | 
| Q2 | **Maximum bundle size?** | No hard limit in the wire format (Count is a u16 → 65535). Practical limit is stub size budget (8 KiB reserved section, expandable) and OS loader limits. Recommend operator warning above N=8. |
| Q3 | **Per-payload SGN encoding?** | Yes — each payload gets its own SGN rounds with an independent seed. The fingerprint evaluator runs before any SGN decoder, so each payload's decoder is embedded per-entry in the PayloadEntry's encrypted blob. |
| Q4 | **Bundle format version negotiation?** | The `BundleHeader.Version` field is checked at stub entry; unknown versions → exit clean. No backward-compat obligation since the stub is always freshly generated at pack-time. |
| Q5 | **ELF bundles?** | The wire format is container-agnostic; `InjectStubELF` can host a bundle stub as easily as a single-payload stub. Phase P1 targets PE only; ELF support deferred to P3. |
| Q6 | **Timing-based predicates (RDTSC)?** | Out of scope for this spec. The RDTSC delta anti-debug check already exists (`AntiDebug` flag). A dedicated timing predicate (e.g., "RDTSC > threshold means VM") could be added as `PT_TIMING` in a future predicate type extension without breaking the wire format. |
| Q7 | **Payload ordering attack?** | An analyst who can run the binary multiple times with patched PEB values can enumerate all predicates. This is expected; the format does not claim security against an interactive attacker who can run arbitrary code on the same machine. |
| Q8 | **Key storage in PayloadEntry?** | Storing the per-payload XOR key in the PayloadEntry is trivially reversible once the binary is captured. This spec uses XOR-only encryption; a stronger design would derive the key from the fingerprint result (e.g., hash of vendor_string + build_number as the key) so the key is not on disk. Deferred to C6-phase-2. |

---

## 10. Reference Implementation Notes

### 10.1 CPUID vendor read (amd64 asm, 25 bytes)

```nasm
; Input: none
; Output: [rsp-12] = 12-byte vendor string (caller must have 12 bytes below rsp)
xor eax, eax          ; EAX = 0 (CPUID leaf 0)
cpuid                 ; EBX:ECX:EDX = vendor string
mov [rsp - 12], ebx   ; bytes 0–3
mov [rsp - 8],  edx   ; bytes 4–7
mov [rsp - 4],  ecx   ; bytes 8–11
```

Note the unusual order: CPUID EAX=0 returns vendor as EBX+EDX+ECX, not
EBX+ECX+EDX. Intel/AMD strings are both 12 bytes; the correct order is
EBX → EDX → ECX (verified against x86 manual and Go's `cpu.x86` package).

### 10.2 PEB build number read (amd64 asm, 9 bytes)

```nasm
; Output: EAX = OSBuildNumber (DWORD at PEB+0x120)
mov rax, gs:[0x60]      ; RAX = PEB*
mov eax, [rax + 0x120]  ; EAX = OSBuildNumber
```

PEB offsets (Windows 10 and later, x64 only):
- `0x118`: `OSMajorVersion` (DWORD)
- `0x11C`: `OSMinorVersion` (DWORD)
- `0x120`: `OSBuildNumber` (DWORD)
- `0x124`: `OSCSDVersion` (DWORD)

These are confirmed stable from Windows 7 through Windows 11 23H2 via
public WinDbg kernel dumps and the ReactOS PEB definition. Server SKUs use
the same offsets.

### 10.3 Bundle stub size budget

| Component | Estimated bytes |
|-----------|----------------|
| Anti-debug prologue (optional) | ~70 |
| CPUID + PEB read | ~35 |
| Fingerprint evaluation loop (N=4) | ~120 |
| Payload decryptor (XOR loop) | ~30 |
| CALL+POP+ADD prologue | 12 |
| SGN decoder (3 rounds, no compress) | ~120 |
| OEP epilogue (ADD + JMP) | ~7 |
| **Total (N=4, no compress)** | **~394** |

The current stub section reserves 4 KiB (non-compress) or 8 KiB (compress).
A 394-byte evaluator+decoder fits comfortably in either budget. For larger N,
the fingerprint loop grows by ~30 bytes per additional entry, remaining under
4 KiB for N ≤ 100.

---

## 11. Summary Table

| Item | Choice |
|------|--------|
| Wire format | Flat binary, 4-region layout, v1 header |
| Fingerprint predicates | CPUID vendor (12 bytes), Win build range, feature mask |
| Predicate logic | AND within entry, first-match across entries |
| Key storage | Per-payload, in PayloadEntry (plaintext in v1) |
| Stub flow | Evaluator prefix → payload selector → XOR decrypt → SGN decode → JMP |
| Fallback | Configurable: exit(0) / first-payload / loudcrash |
| Phase plan | P1 single-target, P2 fingerprint asm, P3 evaluator loop, P4 multi-encrypt |
| Threat model | Defeats hash-batch, per-sandbox analysis; does not defeat forced-execution or emulation |
