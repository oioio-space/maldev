---
last_reviewed: 2026-05-08
reflects_commit: c5ee850
---

# Worked examples

[← docs index](../index.md)

End-to-end runnable scenarios that compose multiple maldev
packages. Each page walks through one operator workflow with
code, build instructions, and honest limitations.

| Scenario | Layers chained | Page |
|---|---|---|
| Basic implant skeleton | recon · evasion · inject · sleepmask · cleanup | [basic-implant.md](basic-implant.md) |
| Evasive injection chain | preset · CET · phantomdll · stealthopen · sleepmask | [evasive-injection.md](evasive-injection.md) |
| Full red-team chain | masquerade · inject · sleepmask · C2 · token · cleanup | [full-chain.md](full-chain.md) |
| DLL proxy side-load | recon/dllhijack · pe/parse · pe/dllproxy · stealthopen · timestomp | [dllproxy-side-load.md](dllproxy-side-load.md) |
| UPX-style packer + cover | pe/packer · transform · cover layer | [upx-style-packer.md](upx-style-packer.md) |
| Multi-target bundle (C6) | pe/packer.PackBinaryBundle · SelectPayload · cmd/packer bundle | [multi-target-bundle.md](multi-target-bundle.md) |

## Conventions

Every example page follows the same shape:

1. **Goal** — one paragraph, what the operator gets.
2. **Chain diagram** — Mermaid flowchart of the pipeline.
3. **Code** — copy-pasteable Go that compiles against current
   master.
4. **Run + verify** — the exact commands a reader can paste.
5. **Hardening dials** — knobs the operator can flip without
   re-architecting.
6. **Limitations** — honest reading of where the technique
   stops working.
7. **See also** — sibling examples + tech md + design docs.

## See also

- [docs/by-role/operator.md](../by-role/operator.md) — operator-
  focused index of techniques + chains
- [docs/index.md](../index.md) — per-technique reference pages
  (categorized by package + MITRE ATT&CK ID)
- [docs/refactor-2026-doc/packer-design.md](../refactor-2026-doc/packer-design.md)
  — design-doc family for packer-related work
