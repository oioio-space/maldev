---
status: review / planning
created: 2026-05-12
last_reviewed: 2026-05-12
reflects_commit: 7d71de2
---

# Packer — zones d'ombre, améliorations, refactorisations possibles

> Audit critique du `pe/packer` après la session EXE→DLL
> (v0.124–v0.129). Objectif : identifier les gaps, les hacks
> qu'il faudrait nettoyer, et les features qui manqueraient
> pour boucler le périmètre opérationnel.

## TL;DR

| Catégorie | Items |
|---|---|
| **Findings empiriques validés (cette session)** | 3 — args propagation Mode 3 ✅, args propagation Mode 3+RandomizeAll ✅, **args injection Mode 8 manquante** |
| **Zones d'ombre fonctionnelles** | 5 — args injection (concern utilisateur), TLS/SEH support, stack cookies/GS, exit code/IO, signed cert preservation |
| **Refactorisations recommandées** | 6 — SGN body dedup, prologue dedup, walker interface, proxy emitter dedup, Mode dispatch builder, BSS chunk constants |
| **OPSEC tighten** | 4 — `.mldv`/`.mldrel` defaults, stub framing signature, PEB-walk pattern, forwarder strings |
| **Coverage gaps** | 3 — PE32 (32-bit), ARM64, MSVC `cl.exe` exports fixture |

## Findings empiriques 2026-05-12 — args propagation

### ✅ Mode 3 (PackBinary EXE) — args propagés correctement

```
exec.Command("packed.exe", "foo", "bar", "baz with spaces")
→ os.Args = [packed.exe, foo, bar, "baz with spaces"]
```

Mécanisme : Windows loader écrit la commandline dans
`PEB.ProcessParameters.CommandLine` AVANT d'invoquer l'OEP.
Notre stub n'y touche pas → le runtime Go (ou le CRT MSVC)
lit depuis PEB normalement via `GetCommandLineW`.
**Validé E2E** : `TestPackBinary_Args_Vanilla_E2E` +
`_RandomizeAll_E2E`.

### ⚠️ Mode 8 (ConvertEXEtoDLL) — args du LOADER seulement

```
rundll32.exe packed.dll,DllMain operator-arg-1
→ payload voit os.Args = [rundll32.exe, packed.dll,DllMain, operator-arg-1]
```

Le payload tourne dans un thread spawné par
`CreateThread(NULL, 0, OEP, NULL, 0, NULL)` à l'intérieur du
host. `GetCommandLineW` lit le PEB du PROCESSUS HOST, donc
l'opérateur ne peut influencer les args qu'à travers la
commandline du loader (sale : visible dans Process Explorer,
laisse une trace IOC).

**Pas de mécanisme actuel pour injecter des args scopés au
payload.** C'est exactement le concern #1 + #2 utilisateur.

### Améliorations proposées pour les args en Mode 8

| Approche | Pro | Con | Effort |
|---|---|---|---|
| **(a) Bake args dans la stub section** + stub mute `PEB.ProcessParameters.CommandLine` avant `CreateThread` | Args invisibles dans la cmdline du host | **Corrompt le PEB du host** — autres composants du host qui lisent CommandLine voient l'override (sale, side-effect) | ~150 LOC |
| **(b) Custom export `RunWithArgs(LPCSTR args)`** au lieu de DllMain auto-spawn | Propre, scopé. Le loader appelle DllMain (no-op), opérateur appelle l'export après | Force un workflow non-standard (operator doit `GetProcAddress`+`CreateRemoteThread` manuellement). Casse le modèle "drop le DLL et c'est fini" | ~200 LOC |
| **(c) Bake args dans la stub section, restaure le PEB après que le payload exit** | Compromis | Payload doit signaler son exit. Race conditions. | ~250 LOC |
| **(d) `RunWithArgsThread` export retournant un HANDLE** | Le plus propre — operator API claire | 2× CreateThread (loader's + ours), plus de complexité | ~250 LOC |

**Recommandation** : (b) en first-cut + documenter (a) comme
opt-in plus tard si le marché le demande. (a) est tentant mais
les side-effects sur le host sont opérationnellement dangereux.

## Zones d'ombre fonctionnelles

### Z1 — TLS callbacks rejection systématique

`PlanPE` rejette tout EXE avec TLS callbacks via
`transform.ErrTLSCallbacks`. Ça exclut **tout binaire mingw
default + de nombreux MSVC C++** (les destructeurs globaux
passent par TLS callbacks).

**Workaround documenté** : build `-nostdlib`. **Limite réelle**
: payloads C++ riches inaccessibles.

**Améliorations possibles** :
- Détecter quels TLS callbacks sont "bénins" (juste constructeurs/destructeurs CRT) et les laisser tomber
- Émettre un stub qui patche temporairement le TLS callbacks array dans le PE pour le neutraliser pendant le décrypt, puis le restaurer
- Ou simplement documenter plus visiblement les options de build qui évitent TLS

### Z2 — Stack cookies (`/GS`) intéraction avec stub

Les binaires MSVC `/GS` injectent un check `__security_cookie`
au prologue de chaque fonction. Le cookie est initialisé
par `__security_init_cookie()` au démarrage. Notre stub
décrypte `.text` (qui contient ces checks) puis JMPs à OEP.
Si OEP est `mainCRTStartup` qui appelle
`__security_init_cookie` avant `main`, **ça devrait marcher**.

**Mais non testé empiriquement.** À ajouter au corpus de
tests : un fixture MSVC `/GS` (besoin d'avoir cl.exe — pas
disponible sur la VM actuellement).

### Z3 — Exit code + stdout/stderr en Mode 8 (ConvertEXEtoDLL)

Le payload tourne dans un thread spawné. Conséquences :
- **Exit code du payload est perdu** — la valeur retournée
  par le thread est récupérable via `GetExitCodeThread` mais
  l'opérateur n'a pas de handle au thread (le DLL ne le
  retourne pas).
- **stdout/stderr** héritent des handles du host. Si le host
  est une GUI app sans console, les `printf` / `os.Stdout`
  du payload sont jetés silencieusement.

**Améliorations** :
- Retourner le HANDLE du thread via un export
  `GetPayloadThread() HANDLE` (1 line export, optional)
- Documenter le pattern "tee stdout vers un fichier" pour
  les cas GUI host

### Z4 — Cert preservation (vs strip)

`v0.126.0` strip `DataDirectory[SECURITY]`. C'est le bon
défaut (clean unsigned > broken signed). **Mais** un opérateur
qui veut DÉLIBÉRÉMENT laisser le cert (par exemple pour
maintenir l'apparence d'un binaire signé sur un audit
visuel rapide) n'a pas d'opt-out.

**Amélioration** : `PackBinaryOptions.PreserveSecurityDir
bool` (default false = strip = current behaviour).

### Z5 — `MonitorBoundary` / `Compress + DLL` mode 7

Mode 7 (FormatWindowsDLL natif) **ne supporte pas Compress**
(`stubgen.ErrCompressDLLUnsupported`). C'est la même feature
que Mode 8 (slice 5.7) — la mécanique LZ4 inflate existe,
elle n'a juste pas été threadée dans le DllMain stub natif.
Estimation ~80 LOC + un E2E.

## Refactorisations recommandées

### R1 — SGN-rounds body dedup (3 copies)

Slice 5.5.y notes mentionne :
> Deferred: SGN-rounds body (3 copies) + DllMain spill/restore
> (2 copies) dedup → separate Tier 🟡 cleanup commit.

`emitSGNRounds` existe déjà comme helper partagé. Mais il y
a encore du code dupliqué dans `EmitStub`, `EmitDLLStub`,
`EmitConvertedDLLStub` autour des prologues + LZ4 inflate
+ memcpy memcpy. ~100 LOC à mutualiser.

### R2 — Walker interface unifié

3 walkers : `WalkBaseRelocs`, `WalkImportDirectoryRVAs`,
`WalkResourceDirectoryRVAs`. Chacun a sa propre signature
mais le pattern est identique : "yield uint32 file offsets
the caller patches".

```go
// proposé
type WalkerCallback func(rvaFileOff uint32) error
type DirectoryWalker func(pe []byte, cb WalkerCallback) error

var DirectoryWalkers = map[int]DirectoryWalker{
    DirImport:   WalkImportDirectoryRVAs,
    DirResource: WalkResourceDirectoryRVAs,
    // ... DirBaseReloc has different sig, would need adapter
}
```

Permet à `ShiftImageVA` de boucler sur la map au lieu de
3 appels manuels. Ouvre la porte à des walkers EXCEPTION /
LOAD_CONFIG / EXPORT futurs en plug-and-play.

### R3 — Proxy emitter dedup (chained vs fused)

`PackChainedProxyDLL` et `PackProxyDLL` partagent ~40 LOC
de validation d'admission (TargetName, Exports). Extraire
`validateProxyOpts(target, exports) error`. Petit gain mais
réduit le risque que les deux drift.

### R4 — Mode dispatch builder pattern

`PackBinaryOptions` a 19 champs maintenant (Format,
Stage1Rounds, Seed, Key, AntiDebug, Compress, ConvertEXEtoDLL,
DiagSkip*×3, RandomizeXxx×8). Toutes les combos ne sont pas
valides ; certaines sont silently no-op (e.g. RandomizeImageBase
sur ELF). Builder pattern aurait l'avantage d'invalider à la
compilation les combos impossibles.

```go
// proposé
opts := packer.NewPackBinaryOpts().
    AsWindowsExe().
    WithRounds(3).
    WithCompress().
    WithRandomizeAll().
    Build() // returns PackBinaryOptions or panics on invalid combo
```

Risque : casse l'API actuelle, multiplie les types. **Pas
recommandé** sauf si la croissance des opts continue.

### R5 — `Disp` constants extraction

Plein de magic numbers `0x20da`, `0x20db`, etc. dans les
displacements stub. Slice 5.5.y a déjà nommé
`convertedDLLFrameSize`, `createThreadCallFrameSize`. Encore
d'autres à nommer (les disps d'AntiDebug, les offsets
LZ4 setup).

### R6 — `pe/packer/transform/peconst.go` dedup avec `pe/packer/runtime`

Les deux ont des PE constants quasi-identiques. Slice 1 du
DLL plan a fait un dedup partiel (`ImageFileDLL` promu de
runtime à transform). À continuer.

## OPSEC à durcir

### O1 — `.mldv` / `.mldrel` default section names

Identifiants triviaux pour YARA. `RandomizeStubSectionName`
existe mais est OPT-IN. **Recommandation** : faire opt-OUT
(default = randomize). Casse la reproducibilité bit-for-bit
pour les opérateurs qui ne settent pas Seed, mais c'est le
comportement attendu pour un packer offensif.

### O2 — Stub framing signature

CALL+POP+ADD = pattern Metasploit/SGN classique. Tous les
stubs partent par `55 48 89 e5` (push rbp; mov rbp, rsp) =
prologue Win64 standard. Détectable par byte-pattern.

**Améliorations** :
- Variantes du prologue (sub rsp,0x30 sans frame pointer ;
  push rbx; mov rbx, rsp ; etc.)
- Insertion de NOP polyforms entre les instructions (la poly
  engine SGN existe pour la décrypt loop, mais pas le frame
  setup)

### O3 — PEB-walk pour kernel32 resolution

Bien connu (Metasploit, Cobalt Strike). Defenders ont des
sigs. Difficile à éviter complètement (alternative serait
import statique de kernel32, mais ça révèle exactement ce
qu'on essaie de cacher).

### O4 — Forwarder strings GLOBALROOT scheme

`\\.\GLOBALROOT\SystemRoot\System32\version` est la signature
"perfect-dll-proxy". `dllproxy.PathScheme` permet d'autres
schémas mais le default = GLOBALROOT.

**Amélioration** : alterner entre les 3 PathScheme par défaut
de manière random per-pack.

## Coverage gaps

### C1 — PE32 (32-bit Windows)

`PlanPE` checke `IMAGE_FILE_MACHINE_AMD64` implicitement via
les offsets PE32+. Inputs PE32 (32-bit) seraient mal-parsed.
Pas de message d'erreur clair — soit silent breakage, soit
crash.

**Action** : ajouter check explicite `Machine == 0x8664` au
start de `PlanPE` et émettre `transform.ErrUnsupportedMachine`
sinon.

### C2 — ARM64 PE binaries

Même histoire que C1, scope plus restreint. Win11 ARM laptops
existent mais cible opérationnelle marginale.

### C3 — MSVC `cl.exe` exports fixture

Toutes les Mode 7/8/9/10 E2E utilisent soit Go static-PIE
soit mingw `-nostdlib`. **Aucune validation contre une vraie
DLL MSVC avec exports nommés.** Provisionner cl.exe sur la
WinVM débloquerait le test `GetProcAddress` sur des exports
réels (pas juste forwarders).

## Findings sécurité / Production

### S1 — Pas d'integrity check post-pack

Si l'opérateur diff le binaire packé entre 2 exécutions
(même Seed), il devrait obtenir des bytes identiques. Si
quelqu'un a tampered avec les bytes entre temps, on ne le
détecte pas. **Pas critique** (le runtime crashe ou ne
décrypte pas), mais une `PackBinaryOptions.IntegrityCheck`
bool optionnel pourrait insérer un CRC32 in-stub vérifié au
runtime.

### S2 — Pas de Wipe-after-decrypt

Une fois `.text` décrypté en RWX, les bytes décodés sont en
mémoire. Si quelque chose dump le process (Defender memory
scan, debugger attach), tout est lisible. La page reste RWX
et reste full-decoded jusqu'à exit.

**Amélioration** : variant "decrypt → execute → wipe" qui
clear `.text` après que OEP a fini. Difficile car on ne sait
pas quand OEP "a fini" (peut être un long-running daemon).
Pas trivial.

### S3 — Pas de jitter / sleep mask integration

`evasion/sleepmask` existe dans le repo. Le packer ne le
compose pas — opérateur doit le wrapper séparément. Composition
naturelle : pendant que le payload sleep, encrypt `.text`
avec une key différente, decrypt avant le wake. Future work
(`Phase 4 — runtime obfuscation`).

## Plan d'action recommandé (priorité)

| # | Item | Effort | Valeur opérationnelle |
|---|---|---|---|
| 1 | (b) Custom `RunWithArgs` export pour Mode 8/10 | ~200 LOC | High — débloque ton concern utilisateur |
| 2 | Mode 7 + Compress (Z5) | ~80 LOC | Medium — feature symétrie |
| 3 | RandomizeStubSectionName ON par défaut (O1) | ~5 LOC + tests update | High — OPSEC win immédiat |
| 4 | PE32+ Machine check explicite (C1) | ~10 LOC | Low (silent breakage rare en prod) |
| 5 | Walker interface unifié (R2) | ~150 LOC + tests | Low — refacto interne sans impact opérationnel |
| 6 | SGN body dedup (R1) | ~100 LOC | Low — pure cleanup |
| 7 | MSVC fixture provisioning (C3) | ~setup VM + 1 fixture | Medium — débloque tests réels |
| 8 | Cert preservation opt-out (Z4) | ~30 LOC | Low — niche use case |

Items #1, #2, #3 = quick high-value wins. Items #4–8 = quand
y'a du temps.

## Cross-reference

- Empirical args tests : `pe/packer/packer_e2e_args_windows_test.go`
- Plans actifs :
  - `packer-exe-to-dll-plan.md` (slices 5+6 ✅ shipped)
  - `packer-dll-format-plan.md` (slices 1-4.5 ✅ shipped)
  - `packer-2f3c-walker-suite-plan.md` (IMPORT + RESOURCE shipped, autres on-demand)
- Session récente : `HANDOFF-2026-05-12.md`
