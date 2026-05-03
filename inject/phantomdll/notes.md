# inject/phantomdll — internal notes

> Internal note (not shipped to /docs). Resolves backlog row P2.9
> "Re-read the source + write a notes block explaining the two-step
> contract" — the row author found the API confusing and asked
> whether `KernelCallbackExec` should accept a remote shellcode
> address instead of `[]byte`.

## What the two functions actually do

`inject` ships two adjacent primitives that look related but
implement disjoint mechanisms:

### `PhantomDLLInject(pid, dllName, shellcode, opener) error`

**Mechanism:** memory placement, file-backed image masquerade.

1. Open `System32\<dllName>` (e.g. `KernelBase.dll`) via the
   operator's `Opener`.
2. `NtCreateSection(SEC_IMAGE)` over the file handle — kernel
   parses the PE and sets up a memory-mapped image view as if
   the DLL were genuinely loaded.
3. `NtMapViewOfSection` into the target process — at this point
   the target has an `MEM_IMAGE`/`SEC_IMAGE`-backed region whose
   `MappedFileName` field reports `\Device\HarddiskVolumeN\Windows\System32\<dllName>`.
4. `VirtualProtectEx` the `.text` section to RW, `WriteProcessMemory`
   the shellcode bytes over `.text`, restore RX.

**What it does NOT do:** trigger execution. The shellcode sits at
`<remoteBase + textRVA>`, RX, and waits for a thread to call into
it. Operators must arrange that separately (CreateRemoteThread,
APC queue, kernel callback, …).

**Why this is valuable on its own:** memory scanners (Defender,
CrowdStrike) treat `MEM_IMAGE` regions backed by a Microsoft-signed
System32 file very differently from `MEM_PRIVATE` RX pages — the
latter are flagged on first-pass enumeration (`VirtualQueryEx` walks)
while the former pass scrutiny because the backing file is on disk
and signed. The shellcode is invisible to a `MappedFileName`-based
allow-list.

### `KernelCallbackExec(pid, shellcode, caller) error`

**Mechanism:** execution trigger via PEB callback table hijack.

1. `OpenProcess(PROCESS_VM_*)`, `NtQueryInformationProcess` to
   read the target's PEB address.
2. Read `PEB+0x58` (the `KernelCallbackTable` pointer) from the
   target's PEB.
3. Read entry index 3 (`__fnCOPYDATA`) — save the original pointer.
4. **Allocate a fresh RWX page in the target** via `VirtualAllocEx`,
   write the shellcode bytes, flip to RX.
5. Overwrite `__fnCOPYDATA[3]` with the new RX address.
6. `SendMessage(target_hwnd, WM_COPYDATA, …)` — `user32` invokes
   the kernel callback table entry, which now points at our
   shellcode. Shellcode runs synchronously on the target's UI
   thread.
7. After return, restore the original `__fnCOPYDATA` pointer.

**What it does NOT do:** rely on any prior memory placement. Step 4
is self-contained — the shellcode bytes the operator passes to
`KernelCallbackExec` are written into a private RWX page allocated
by `KernelCallbackExec` itself.

## The "two-step contract" question

The backlog row asks: *if PhantomDLLInject just placed shellcode and
KernelCallbackExec needs a memory address, why does KernelCallbackExec
take `[]byte` instead of a `uintptr`?*

The answer is that **KernelCallbackExec is not a sibling of
PhantomDLLInject — it is a sibling of CreateRemoteThread,
NtQueueApcThreadEx, and SectionMapInject.** All four are
self-contained injection primitives: each one picks its own memory
placement strategy and triggers execution off that placement. The
operator picks one based on the desired tradeoff:

| Primitive | Memory placement | Execution trigger |
|---|---|---|
| `CreateRemoteThread`-based executor | `VirtualAllocEx(RWX)` | `CreateRemoteThread` |
| `inject.SectionMapInject` | `NtCreateSection` + `NtMapViewOfSection` (private) | `CreateRemoteThread` |
| `QueueAPCExecutor` | `VirtualAllocEx(RWX)` | `NtQueueApcThreadEx` (alertable) |
| `KernelCallbackExec` | `VirtualAllocEx(RW→RX)` | `WM_COPYDATA` callback hijack |
| `PhantomDLLInject` | `NtCreateSection(SEC_IMAGE)` + `.text` overwrite | **none** — placement only |

`PhantomDLLInject` is the **only** primitive in this family that
splits placement from execution. It exists for the operator who
wants the file-backed image masquerade without committing to a
specific trigger.

## Is the API genuinely redundant?

The redundancy the row author intuited would arise if an operator
called both:

```go
phantomdll.PhantomDLLInject(pid, "KernelBase.dll", sc, opener) // places sc at <imgBase + textRVA>
inject.KernelCallbackExec(pid, sc, caller)                     // allocs new RWX, writes sc there too
```

Both end up with `sc` in the target — but at two different
addresses, and only the `KernelCallbackExec` copy actually runs.
The PhantomDLL placement is dead weight in this combination.

**The right combination — currently unsupported by the API — is
"phantom-place then trigger by remote address":**

```go
imgBase, textRVA, err := phantomdll.PhantomDLLPlace(pid, "KernelBase.dll", sc, opener)
inject.KernelCallbackExecAt(pid, imgBase+textRVA, caller)
```

This needs:

1. `PhantomDLLPlace(...) (remoteBase uintptr, textRVA uint32, err error)` — splits the current `PhantomDLLInject` so callers can recover the placement coordinates.
2. `KernelCallbackExecAt(pid, remoteAddr, caller)` — variant that **skips its own VirtualAllocEx + WriteProcessMemory** and points the callback at an existing RX address. Restores the original callback after execution as today.

Same change applies to `QueueAPCExecutor` and the
`CreateRemoteThread` executors — they all currently bundle
allocation+write into the executor, which prevents composition with
phantom-style placement primitives.

## Recommendation

The row offers two follow-ups:

- **Refactor (breaking change → semver bump):** add the
  `*Place` / `*ExecAt` decomposition outlined above. Old call sites
  still compile because the all-in-one functions stay; new call
  sites get genuine composability.
- **E2E test in the VM matrix:** lock the contract with a test that
  asserts `PhantomDLLInject + KernelCallbackExec` (the naive
  combination) writes shellcode at two addresses but only one ever
  executes, while `PhantomDLLPlace + KernelCallbackExecAt` (the
  composed combination) writes once and executes from the
  file-backed image.

The first row of P2.9 is now closed by this notes file. Whether to
proceed with the refactor is a scope decision that needs operator
input — the breaking change costs every external consumer that
already calls `KernelCallbackExec(pid, shellcode, caller)`.
