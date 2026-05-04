---
package: github.com/oioio-space/maldev/recon/network
last_reviewed: 2026-05-04
reflects_commit: 7a8c466
---

# IP address & local-network detection

[← recon index](README.md) · [docs/index](../../index.md)

## TL;DR

Cross-platform IP enumeration ([`InterfaceIPs`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network))
and local-address detection ([`IsLocal`](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network)).
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

### `func InterfaceIPs() ([]net.IP, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#InterfaceIPs)

Walks `net.Interfaces` + each interface's `Addrs` and returns
every assigned IP (loopback + physical + virtual + VPN).

**Returns:** flat `[]net.IP`; error from
`net.Interfaces` or any interface's `Addrs`.

**OPSEC:** stdlib network enumeration — invisible to user-mode
EDR. The kernel-side syscalls (`ioctl SIOCGIFCONF` on Linux,
`GetAdaptersAddresses` on Windows) are universal.

**Required privileges:** none.

**Platform:** cross-platform.

### `func IsLocal(IPorDN any) (bool, error)`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#IsLocal)

Decides whether the input — `net.IP`, IP-literal string, or
hostname — resolves to one of the host's own interface
addresses.

**Parameters:** `IPorDN` — `net.IP`, IP-literal string, or
hostname. Any other type returns `ErrNotIPorDN`.

**Returns:** `true` when at least one resolved address matches
an interface IP; error from `net.LookupIP` (wrapped as
`ErrNotIPorDN` on resolution failure) or from the underlying
`InterfaceIPs` call.

**Side effects:** triggers DNS resolution for hostname inputs.

**OPSEC:** the DNS query for an arbitrary hostname is logged
end-to-end; do not pass the implant's own C2 domain to
`IsLocal`.

**Required privileges:** none.

**Platform:** cross-platform.

### `var ErrNotIPorDN`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/recon/network#ErrNotIPorDN)

Sentinel returned by `IsLocal` when the input is neither a
`net.IP`, an IP literal, nor a resolvable hostname.

**Platform:** cross-platform.

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
