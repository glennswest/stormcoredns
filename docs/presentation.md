---
marp: true
title: stormcoredns
description: CoreDNS in Rust, the cluster DNS of stormcos. Its purpose and what it does today
paginate: true
size: 16:9
style: |
  section { font-size: 23px; }
  h1 { font-size: 40px; }
  h2 { font-size: 31px; }
  pre, code { font-size: 16px; }
  table { font-size: 18px; }
---

<!-- Render: npx @marp-team/marp-cli@4 docs/presentation.md -o out/presentation.html
     (add --pdf for PDF). Written 2026-09-26 for v0.1.1 at 71dc634 (#4), after
     the docs were rewritten from the code (#3). Every claim here can be checked
     against the code. README.md, docs/plugins.md and docs/integration.md give
     the file for each. -->

# stormcoredns

**CoreDNS, reimplemented in Rust. The cluster DNS of stormcos.**

It uses the same Corefile, the same plugin names and chain order, the same
flags, and the same metric names and HTTP endpoints. A kube-dns ConfigMap
runs unchanged.

v0.1.1 · tracks CoreDNS 1.12 · `glennswest/stormcoredns` · Rust, one static binary

---

## The problem it solves

A cluster without DNS is one almost no workload can run on: a Service has to
be reachable by name, or it may as well not exist.

- **Kubernetes needs cluster DNS.** `svc.ns.svc.cluster.local`, SRV, PTR and
  headless endpoints, all kept current from the API server.
- **Upstream CoreDNS is Go, and a pulled image.** stormcos builds every
  component from source into a golden that records the commit it came from.
- **stormcoredns is that component.** It builds from source, into one static
  musl binary with no userland, and needs no manifest changes beyond the
  image and the path to the binary.

It forwards to MicroDNS and does not replace it. MicroDNS stays authoritative
for the site zones and owns DHCP and IPAM. stormcoredns answers only
`cluster.local`.

---

## Where it sits in stormcos

```text
   stormcos ──composes──▶ coredns golden ◀── stormcoredns (this repo, built from source)
                              │ /pallets/coredns
   rustkube-node + stormpump ─┴─▶ run the pod (80-coredns.yaml, command: /coredns)
                                        │ list + watch
                         rustkube ◀─────┘   (services, namespaces, endpoints[lices], pods)
                                        │ forward . 192.168.8.252
                         MicroDNS ◀─────┘   (site zones; not a stormcentral project)
   every pod ──resolv.conf──▶ kube-dns Service 10.96.0.10 ──▶ stormcoredns
```

- **stormcentral's graph:** stormcos → stormcoredns → `stormd`. The stormd edge
  is wrong, because the golden is a bare binary with no stormd. It should be
  rustkube and rustkube-node (stormcentral#35).
- **Group:** network. **Role:** "CoreDNS in Rust".

---

## How it works

```text
Corefile ──lex/parse (import, snippets, {$ENV})──▶ server blocks
   │  every directive's setup(), sorted into plugin.cfg order (53 directives)
   ▼
ServerConfig per key  ──group by (transport, bind addr)──▶  Server
   │                                                           │
 UDP·TCP·DoT·DoH·DoQ·gRPC listeners (SO_REUSEPORT)             ▼
   └──▶ longest zone match → first view that accepts → plugin chain
            errors → … → cache → rewrite → … → kubernetes → file → forward
            each plugin answers, or calls next.serve() and edits the reply
   ◀── encode at the client's EDNS size (TC if it does not fit) ◀──┘
```

- `Handler::serve_dns(req, next)` returns the **reply as a value**
  (`Msg`/`Rcode`/`Drop`/`Multi`), where CoreDNS wraps a ResponseWriter.
- `self_lookup` resolves a name through the server's own chain, the way
  CoreDNS's `upstream` does. It is used for CNAME chasing and dns64.
- Reload starts the new instance before the old one stops. A bad Corefile
  keeps the old instance running.

---

## Cluster DNS: what the kubernetes plugin serves

| name | answer |
|---|---|
| `svc.ns.svc.cluster.local` | ClusterIP, or the ready endpoint IPs if headless |
| `_port._proto.svc.ns.svc.cluster.local` | SRV |
| `<hostname\|dashed-ip>.svc.ns.svc.cluster.local` | endpoint; pod name with `endpoint_pod_names` |
| `1-2-3-4.ns.pod.cluster.local` | with `pods insecure\|verified` |
| reverse zones | PTR for service and ready-endpoint IPs |
| ExternalName | CNAME, chased through `forward` for A/AAAA |
| apex | SOA, NS `ns.dns.cluster.local`, `dns-version` TXT |

- **EndpointSlices, or core Endpoints.** It asks discovery at startup, so
  rustkube does not need EndpointSlices.
- **`/ready` turns 200** once every watched kind has finished its first list.
- **Proven on stormcos 11.03** (2026-09-21):
  `kubernetes.default.svc.cluster.local` → `10.96.0.1`.

---

## What it does today: the plugin set

All **53** directives of CoreDNS 1.12's `plugin.cfg` are recognised and
implemented (`-plugins` lists them):

| area | plugins |
|---|---|
| cluster DNS | `kubernetes` `k8s_external` `autopath` `forward` `cache` `loop` `loadbalance` `reload` `health` `ready` `prometheus` `errors` |
| queries | `rewrite` `template`* `hosts` `acl` `view`* `cancel` `bufsize` `dns64` `any` `local` `minimal` `header` `nsid` `chaos` `whoami` `erratic` |
| authoritative | `file`* `auto` `secondary`* `transfer` `dnssec`* `sign`* `tsig`* |
| server | `bind` `tls` `timeouts` `multisocket` `root` `debug` `metadata` `geoip` `on` `log` `dnstap`* `trace`* `pprof`* |
| backends | `etcd` `grpc` `route53`* `azure` `clouddns` |

Unmarked plugins work as in CoreDNS. The plugins marked * work, with gaps
listed on the "Partial, or differs from CoreDNS" slide. The complete per-plugin status, with coded defaults, is in
`docs/plugins.md`.

---

## What it does today: transports

A server-block key is `[scheme://]zone[:port]`:

| scheme | port | notes |
|---|---|---|
| `dns://` | 53 | UDP and TCP, dual stack; `-dns.port` or `PORT` change it |
| `tls://` | 853 | DNS-over-TLS; needs `tls` |
| `https://` | 443 | DoH at `/dns-query`, GET `?dns=` or POST |
| `quic://` | 853 | DoQ; needs `tls` |
| `grpc://` | 443 | `coredns.dns.DnsService/Query` |

- **Stream transports pipeline.** Each query is answered as it completes.
- **Default timeouts** are idle 10 s and read/write 2 s; `timeouts` changes
  them.
- **Zone transfers** go out as ~60 KB messages over TCP and DoT, with NOTIFY
  sent to `to` addresses.

---

## Interfaces: command line and config

```text
stormcoredns -conf FILE        # default "Corefile"
             -dns.port N | -p  # default 53; PORT in the environment wins
             -pidfile FILE  -quiet | -q  -version | -v  -plugins  -h
```

- **Flags use Go syntax.** Any number of dashes, and `-f v` or `-f=v`. The glog
  flags are accepted and ignored.
- **Logs go to stdout**, filtered by `STORMCOREDNS_LOG`, then `RUST_LOG`
  (default `info`, or `warn` with `-quiet`).
- **The Corefile is CoreDNS's**, with `import`, snippets and
  `{$ENV}`/`{%ENV%}`.
- **Signals:** SIGHUP and SIGUSR1 reload; SIGINT and SIGTERM run the shutdown
  hooks (lameduck), then close the listeners.
- **Identity:** `-version` prints `stormcoredns-0.1.1 (CoreDNS-1.12
  compatible)`, and `coredns_build_info{revision}` carries the git SHA.

---

## Interfaces: health, readiness, metrics

| port | endpoint | meaning |
|---|---|---|
| 53 | DNS | UDP and TCP |
| 8080 | `/health` | 200 `OK`; 503 during lameduck while DNS keeps answering |
| 8181 | `/ready` | 200 once the kubernetes watches have synced; otherwise 503 with the plugin names |
| 9153 | `/metrics` | Prometheus, only as `prometheus :9153`; a bare `prometheus` binds localhost |
| 6053 | `/debug/pprof/` | process statistics (localhost) |

- **Metric names are CoreDNS's:** `coredns_dns_requests_total`,
  `_responses_total`, `_request_duration_seconds`, plus the cache, forward,
  kubernetes, acl, template, dnssec and hosts families, and `build_info` and
  `plugin_enabled`.
- There are **no `process_*` metrics.** The full list is in
  `docs/plugins.md#metrics`.

---

## How it ships

**The `coredns` golden**, a *special* golden built by stormcos's builder in
stage mode:

```bash
sc-build                                                     # build + 54 tests on dev, after git push
stormcentral component stage coredns --url http://stormcentral.g8.lo
```

1. The builder fetches this repo at the pushed commit and runs
   `cargo build --release --target <musl>`.
2. It stages `/stormcoredns`, a `/coredns` symlink and `/etc/coredns/`, a 32M
   golden recorded as `stormcoredns@<sha>`.
3. It seals the golden into forge and files a stormcos release request. The
   latest is `golden-coredns-0f272e81c6e0` (stormcos#107).

There is **no container image and no registry** on this path, and **no
upstream fallback**: if stormcoredns does not build, the release has no
`coredns` golden.

---

## How it starts and is updated

- **Start.** The node clones `pallet:system1/coredns` to `/pallets/coredns`.
  stormcos's `80-coredns.yaml` (the upstream manifest, with `image: coredns`
  and `command: ["/coredns"]`) runs it as the `kube-dns` Deployment behind
  `10.96.0.10`.
- **Configure.** The ConfigMap Corefile forwards to `192.168.8.252` rather
  than `/etc/resolv.conf`, which would point back at itself and loop.
- **Reload.** The `reload` plugin re-hashes the Corefile every 15–30 s, and
  SIGHUP does the same.
- **Update.** Push, run `sc-build`, stage the golden, and the next stormcos
  release carries it.
- **Outside stormcos.** A `Containerfile` (FROM scratch) and
  `deploy/kubernetes/coredns.yaml` are provided, but no registry is published.

---

## Partial, or differs from CoreDNS (from the code)

| | |
|---|---|
| **missing** | `dnssec`/`sign`: no RSA (ECDSA and Ed25519 only), no NSEC3, no CDS/CDNSKEY · `trace`: no exporter · `pprof`: process stats, not Go profiles · `kubernetes multicluster` |
| **partial** | `dnstap`: no FORWARDER messages (#22) · `template`: no Go template functions (#21) · `tsig`: SHA-2 only, AXFR unsigned (#24) · `route53`: no IRSA/IMDS (#23) · `view metadata()`: always empty · `file`: signed zone files do not load (#20) |

The defaults and behaviours the docs audit found were checked against
CoreDNS v1.12.4's source and fixed in #15; options that are accepted and
ignored are listed per plugin in docs/plugins.md.

---

## Planned (not built)

- **Built, not yet run on a machine:** `stormcoredns-test` (`test/`), the
  short/medium/long suites per the stormcos test standard, run as a Job on
  the test machines (#5).
- **Planned:** fixes for the bugs on the next slide, cluster-DNS path first.
- **Planned:** a `trace` exporter (OTLP/Zipkin), NSEC3 in `sign`,
  CDS/CDNSKEY in `sign`, and `kubernetes multicluster`.
- **Planned elsewhere:** stormcentral#35 corrects the graph edges;
  stormcos#79 removes stale claims about an upstream CoreDNS fallback.

---

## Status and open issues that matter

**Status:** v0.1.1. It is the cluster DNS in stormcos releases, and 54 unit
tests pass under `sc-build`. The docs were rewritten from the code (#3).

These bugs are open on the path stormcos runs (`lameduck 5s`, `reload`,
`loop`):

| # | effect |
|---|---|
| #6 | after any reload, `/health` stays at 503, so a liveness probe would restart the pod |
| #7 | one failed reload stops automatic reloads until SIGHUP |
| #8 | after a reload, `:53` listens on IPv4 only |

Also open: #10 dnssec, #11 secondary, #12 view, #21–#24
CoreDNS differences, #20 signed zone files, #5 tests.
