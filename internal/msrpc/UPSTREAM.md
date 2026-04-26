# internal/msrpc — adapted fork of oiweiwei/go-msrpc

Source: https://github.com/oiweiwei/go-msrpc
Upstream commit: `e4f410a7f200bab35af34bae62457dfc82b2a505`
Upstream module path: `github.com/oiweiwei/go-msrpc`
Upstream license: MIT — see `UPSTREAM-LICENSE`

## Why we fork instead of import

1. **Go-version control.** Upstream's `go.mod` declares `go 1.25.0`,
   which would force maldev's `go 1.21` floor up. Forking pins the
   subtree at our floor.
2. **Trim scope.** Upstream is a complete MS-RPC + DCERPC client/server
   stack with hundreds of generated bindings (DRSUAPI, NRPC, SAMR,
   LSARPC, EVENTLOG, …). The first cut needs only PAC NDR marshaling
   for chantier V (Golden Ticket). The transports + bindings stay
   un-vendored until chantier VI (DCSync) needs them.
3. **Caller / Opener / folder.Get threading.** Same policy as
   `internal/krb5/`: any Win32/NT call site or path-based file read
   inside the forked tree gets adapted to accept maldev's optional
   `*wsyscall.Caller` / `stealthopen.Opener` parameters, chantier-by-
   chantier as packages adopt the fork.

## Adaptation policy

License-preserving (MIT — every vendored file keeps its original
copyright header). The trim is destructive (we delete sub-trees we
don't need) but the kept code is untouched except for import-path
rewrites. Any maldev modification that changes observable behavior
is called out at the top of the affected file.

Upstream merges are manual. When pulling new go-msrpc changes, follow
the same procedure as the gokrb5 fork (see `internal/krb5/UPSTREAM.md`):

1. Fetch upstream into `ignore/upstream/go-msrpc/`.
2. Diff against the current `internal/msrpc/` subset.
3. Apply changes file-by-file, re-rewriting imports.
4. Re-run `go test ./internal/msrpc/...`.

## Trim summary

**Kept** (~14k LOC):

- `ndr/` — NDR20 + NDR64 bidirectional marshaler. The piece
  `internal/krb5/pac` is missing (gokrb5/pac is parser-only).
- `msrpc/pac/` — PAC type definitions with full `MarshalNDR()` /
  `UnmarshalNDR()` paths. Pre-staged for chantier V.
- `msrpc/dtyp/` — Common DCERPC data types (RPC_UNICODE_STRING,
  RPC_SID, FILETIME, etc.) — heavily depended on by `msrpc/pac/`.
- `msrpc/adts/claims/claims/v1/` — `ClaimsSetMetadata` type +
  `GoPackage` constant; required because `msrpc/pac/pac.go` and
  `pac_type.go` reference `claims.ClaimsSetMetadata` for
  `PAC_CLIENT_CLAIMS_INFO` / `PAC_DEVICE_CLAIMS_INFO` blocks. We
  keep the full v1.go because gutting it broke the type graph; the
  contained `xxx_DefaultClaimsClient` / `RegisterClaimsServer`
  functions are dead code in our build (no DCERPC transport
  vendored).
- `midl/uuid/` — UUID type used everywhere in the IDL-generated code.
- `text/encoding/utf16le/` — UTF-16LE encoder used by NDR string
  marshalers.
- `internal/math/` — vendored inline copy of `oiweiwei/go-math`
  (~400 LOC, MIT, declares `go 1.23` so we vendor instead of
  importing for the same go-version-floor reason). Provides the
  `FloatFormat` enum (IEEE/Vax/Cray/IBMHex) used by `ndr/`.
- `dcerpc/` — **STUB**. Just enough type machinery (`SyntaxID`,
  `Conn`, `Operation`, `Option`, `CallOption`, `ServerHandle`,
  `WithAbstractSyntax`) so the vendored claims client compiles;
  method bodies are absent — production code that reaches the
  transport hits `ErrStubbed`. PAC marshaling never reaches here.

**Dropped**:

- `dcerpc/` real implementation (replaced by stub).
- `msrpc/pac/pac_credential_info.go` — handled the optional
  PAC_CREDENTIAL_INFO encrypted-credentials section. Not needed for
  golden-ticket forging; dropping it eliminates the
  `oiweiwei/gokrb5.fork/v9` dependency.
- `msrpc/pac/pac_test.go` + `msrpc/pac/testdata/` — upstream's
  PAC parser test suite needs `gokrb5.fork/v9/test/testdata`.
  Maldev-specific tests will land with chantier V's wiring.
- All other `msrpc/*` bindings (DRSUAPI, NRPC, SAMR, LSARPC,
  EVENTLOG, etc.) — out of scope for the first cut. Chantier VI
  will vendor MS-DRSR specifically.
- `dcerpc/v5/` transport implementations — not vendored.
- `idl/`, `midl/` (other than `uuid/`), `examples/`, `test/` — not
  needed.

## External Go modules pulled in by the trim

None new. The vendored subset depends only on:
- Go stdlib
- Maldev-internal: `internal/msrpc/{dcerpc,midl/uuid,ndr,internal/math,text/encoding/utf16le,msrpc/{dtyp,pac,adts/claims/claims/v1}}`

## What this fork does NOT yet adapt

Same policy as `internal/krb5/`: the first cut is verbatim trim with
import paths rewritten + a small dcerpc stub. Caller / Opener
integration points (none in the marshaler subset itself — NDR is
purely byte-level) will land when chantier VI wires DCSync, at which
point a real DCERPC transport replaces the stub and the SSPI
Negotiate path enters from the maldev side via `internal/krb5/`.
