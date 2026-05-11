---
last_reviewed: 2026-05-11
status: reference
---

# Packer debugging toolkit — what's available and when to reach for it

## Tools already in the Win10 VM

Per `scripts/vm-provision.sh`:

- **WER LocalDumps** — Windows Error Reporting writes a full
  user-mode minidump to `C:\Dumps\<exe>.<pid>.dmp` whenever a
  packed binary crashes. Configured registry-only (no install
  needed). Useful when an E2E exit code alone isn't enough.

- **.NET Framework 3.5** — for `pe/clr` CLR tests. Not packer-
  related but available.

## Debugging strategy that worked today

Investigating `RandomizeImageBase` returning
`0xC0000005` ACCESS_VIOLATION (silent crash, no stdout):

1. **Run locally on Windows host first** — much faster than
   the VM round-trip. Most crashes reproduce on the dev box.

2. **Empirical binary search.** Pick 7 specific values
   spanning the parameter range (here: 7 ImageBase values
   from `0x140000000` to `0x7FF000000000`), pack with each,
   run all locally, observe which crash. Result told me
   "only the canonical value works" — which immediately
   implicated the parameter itself rather than a unrelated
   side effect.

3. **Diff the headers.** `packer-vis sections` between the
   working and broken outputs. They were byte-identical
   except for the ImageBase field — proving the structural
   shape was fine and the issue was downstream of headers
   (likely loader rebase math).

4. **Reason from spec.** With the suspect narrowed to
   "ImageBase change breaks something the loader does",
   reading the rebase formula
   `actual_addr = file_value + (actual_base - preferred_base)`
   pinpointed the bug: file values are pre-computed against
   `oldImageBase + RVA`, so changing `preferred_base` without
   adjusting `file_value` gives the loader the wrong delta.

5. **Fix, re-run, confirm.** Walker the reloc table and add
   `(newBase - oldBase)` to each DIR64/HIGHLOW value before
   writing the new ImageBase. All 7 binary-search values
   pass after fix. Win10 VM E2E confirms RandomizeAll (now
   8 opts) green.

**Total time:** ~15 minutes including the fix. No debugger,
no MSDN deep-dive, no VM cycles needed.

## In-tree diagnostic CLIs (preferred over external tools)

Today's debug session was solved entirely with these. Reach
for an external debugger only if these aren't enough.

| Subcommand | What it shows | Built today? |
|---|---|---|
| `packer-vis sections <file>` | Section table + COFF.PointerToSymbolTable. Used to confirm structural shape between two packs. | shipped earlier (Phase 2-F-2 follow-up) |
| `packer-vis directories <file>` | DataDirectory inventory — which of the 16 entries are populated, RVA + size. Tells you which walkers a payload would need. | yes (this commit, promoted from `ignore/dump_loadconfig.go` after it proved its keep) |
| `packer-vis entropy <file>` | Shannon-entropy heatmap. Useful for confirming `.text` is encrypted (high entropy) vs plain (low). | shipped earlier |
| `packer-vis compare <a> <b>` | Stacked entropy heatmaps with delta. The "see the packer at work" view. | shipped earlier |

These three are what an operator actually needs when a packed
binary misbehaves: section structure, directory inventory,
entropy distribution. Three terminals, no SDK install.

## When external tools would actually help

Only if the in-tree CLIs don't isolate the failure:

- **WER minidump in `C:\Dumps`** (already configured) tells
  you the crash address + register state. Read with any
  debugger that consumes minidumps; on the Win10 VM the
  Defender-bundled `werfault.exe` can show a basic dialog,
  or copy the .dmp back to host and load in Visual Studio /
  WinDbg if installed locally.
- **Process Monitor (Sysinternals)** when you suspect a
  missing-DLL or registry-access issue rather than a code
  bug. Single .exe, no installer needed.
- **`dumpbin /headers`** is already covered by
  `packer-vis sections` + `directories` for our use case.

No need to balloon the VM snapshot with debugging tools that
won't get used.

## Operator-recognisable failure codes

| Exit code (decimal / hex) | Symptom | Likely cause | First action |
|---|---|---|---|
| `3221225477` / `0xC0000005` | ACCESS_VIOLATION | Bad pointer dereference. Typically a reloc'd value pointing into garbage. | Empirical bisect on opts; check WER dump in `C:\Dumps`. |
| `3221225781` / `0xC0000135` | DLL_NOT_FOUND | Import resolution failed. Stale RVA in IMPORT directory. | Check IMPORT walker is enabled (it's in v0.104.0+). |
| `3221226505` / `0xC0000409` | STACK_BUFFER_OVERRUN | CFG cookie validation failed. `.text` was modified after CFG was applied. | Don't `PackBinary` CFG-protected payloads — use `PackBinaryBundle` instead. See `packer.md` Known limitations. |
| Loader: "%1 n'est pas une application Win32 valide" | Mapping rejected | SizeOfImage / SizeOfHeaders inconsistency, BaseOfCode out of any section, etc. | Compare PE headers between vanilla pack and faulty pack via `packer-vis sections`. |

## Cross-reference

- Tested-fixture matrix: `docs/techniques/pe/packer.md` →
  "Tested-fixture matrix" section.
- Walker suite: `docs/refactor-2026-doc/packer-2f3c-walker-suite-plan.md`.
- Today's session findings: `docs/refactor-2026-doc/HANDOFF-2026-05-11.md`.
