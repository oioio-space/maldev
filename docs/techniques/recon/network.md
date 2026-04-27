---
package: github.com/oioio-space/maldev/recon/network
last_reviewed: 2026-04-27
reflects_commit: f31fca1
---

# IP address & local-network detection

[← recon index](README.md) · [docs/index](../../index.md)

## TL;DR

Cross-platform IP enumeration ([`InterfaceIPs`](../../../recon/network))
and local-address detection ([`IsLocal`](../../../recon/network)).
Used to fingerprint sandboxes (looped-back /29 networks),
source-aware C2 (avoid beaconing the same IP), and "is this
hostname us?" checks.

## Primer

`InterfaceIPs` walks `net.Interfaces` + each interface's
`Addrs` — same surface every Go network tool uses. Returns a
flat `[]net.IP` covering loopback + physical + virtual + VPN
adapters.

`IsLocal` decides whether a given input — IP literal, FQDN, or
hostname — resolves to one of the host's own interfaces. DNS
resolution runs if the input isn't already an IP literal.
Used for "is this C2 endpoint actually our own host (sandbox
hairpinning)?" probes.

## API Reference

| Symbol | Description |
|---|---|
| [`InterfaceIPs() ([]net.IP, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#InterfaceIPs) | Every IP across every interface |
| [`IsLocal(IPorDN any) (bool, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#IsLocal) | Input is one of host's IPs |
| [`var ErrNotIPorDN`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#ErrNotIPorDN) | Input is neither IP nor parseable hostname |

## Examples

### Simple — list interface IPs

```go
import "github.com/oioio-space/maldev/recon/network"

ips, _ := network.InterfaceIPs()
for _, ip := range ips {
    fmt.Println(ip.String())
}
```

### Composed — avoid C2 self-target

```go
ok, err := network.IsLocal("c2.example.com")
if err == nil && ok {
    // C2 host resolves to our own IP — sandbox hairpin trick;
    // bail out.
    return
}
```

### Advanced — sandbox fingerprint

Sandboxes commonly run on `/29` (8 host) or `/30` networks
with predictable gateway patterns. Combined with [`recon/sandbox`](sandbox.md)
this is one indicator among many.

```go
ips, _ := network.InterfaceIPs()
for _, ip := range ips {
    if ip.IsLoopback() {
        continue
    }
    // narrow nets / private 10.0.0.x are common in sandboxes —
    // calibrate to the target environment
}
```

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| `net.Interfaces` walks | Universal Go runtime call — invisible |
| DNS lookups for `IsLocal` inputs | DNS telemetry sees the query; benign domain looks fine |
| Resolution failure on uncommon TLDs | Sandbox sinkholes resolve everything; real DNS NXDOMAINs |

**D3FEND counters:** none specific.

**Hardening for the operator:** avoid resolving the implant's
own C2 domain via `IsLocal` — the DNS query itself is a
fingerprint.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | full | — |

## Limitations

- **No interface metadata beyond IP.** MAC, MTU, link state
  are out of scope; use `net.Interfaces` directly.
- **DNS overhead.** `IsLocal` on a hostname triggers DNS
  resolution; cache the result for hot paths.
- **No IPv6 hairpin awareness.** `IsLocal` works on IPv6
  literals but does not normalise scopes; link-local addresses
  may behave unexpectedly.

## See also

- [`recon/sandbox`](sandbox.md) — multi-factor environment
  detection.
- [`c2/transport`](../c2/transport.md) — consumer for
  source-IP-aware callback profiles.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
