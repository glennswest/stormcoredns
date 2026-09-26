# CLAUDE.md — stormcoredns

A Rust reimplementation of [CoreDNS](https://coredns.io): same Corefile
syntax, same plugin-chain model, same plugin names and directives, same
external APIs (DNS over UDP/TCP/TLS/HTTPS/QUIC/gRPC, Prometheus metrics,
`/health`, `/ready`, dnstap, reload). Design notes are in
[docs/architecture.md](docs/architecture.md); the plugin authoring contract
is [docs/plugin-api.md](docs/plugin-api.md); per-plugin status is in
[docs/plugins.md](docs/plugins.md).

## Version

`0.1.1` (tag v0.1.1) — defined in `Cargo.toml` only (`src/main.rs` reads
`env!("CARGO_PKG_VERSION")`).

## Build, test, ship

Never build on the stormcentral VM and never `ssh root@` anywhere. Push, then:

```bash
sc-build                        # cargo build && cargo test on dev.g8.lo, scratch dir, deleted after
sc-build 'cargo test cache'     # any command
```

`build.rs` needs `protoc` (tonic-build for `proto/dns.proto`).

It ships as the **`coredns` golden**, built by stormcos's builder in stage
mode (special golden; stormcentral `src/goldens.rs` maps it to
`STORMCOREDNS_SRC`). When an issue's work is pushed and sc-build passes:

```bash
stormcentral component stage coredns --url http://stormcentral.g8.lo
```

No image registry is involved (the mkube registry was retired 2026-08-27);
`Containerfile` and `deploy/kubernetes/coredns.yaml` are for non-stormcos
clusters only. stormcos runs it from `deploy/manifests/80-coredns.yaml`
(`command: ["/coredns"]`, forward to 192.168.8.252). Details:
[docs/integration.md](docs/integration.md).

## Layout

```
src/main.rs            flags (hand-parsed, Go flag style): -conf -dns.port/-p -pidfile -quiet/-q -version/-v -plugins; PORT env; signals; reload loop
src/corefile/          Caddyfile-v1 lexer + parser (import, snippets, {$ENV}/{%ENV%}) + Dispenser
src/plugin/            Handler trait, Next, Request, Reply, PluginError, Controller, registry (plugin.cfg order), replacer
src/server/            key parsing, listener grouping, UDP/TCP/DoT/DoH/DoQ/gRPC, zone+view dispatch, self_lookup
src/plugins/           one module per directive (prometheus = metrics.rs; file/, dnssec/, kubernetes/ are dirs)
src/dnsutil/           name helpers, reverse zones, upstream parsing, EDNS0, durations
src/metrics.rs         global Prometheus registry + core metrics
docs/                  architecture, plugin API, per-plugin status + metrics, stormcos integration
examples/              Corefiles + a zone file
```

## Work plan

Priority order came from the owner (2026-08-29): Kubernetes cluster DNS
first, then the plugins that let one server also serve site zones (the
MicroDNS consolidation path: `view`, `transfer`, `secondary`).

### Phase 1 — core ✅
- [x] Corefile lexer/parser/Dispenser (import, snippets, env vars, blocks)
- [x] Plugin trait, chain, request/reply, registry in plugin.cfg order
- [x] Server: zone dispatch, UDP+TCP, TLS, DoH, DoQ, gRPC listeners, reload/SIGHUP/SIGUSR1
- [x] main.rs CLI matching `coredns` flags
- [x] Smoke-tested on dev: UDP/TCP answers, cache hit, forward, health/ready/metrics

### Phase 2 — essential for a cluster
- [x] errors health ready prometheus forward cache loop reload loadbalance
- [x] log bind debug root whoami
- [x] kubernetes (Services, headless, SRV, PTR, pods, ExternalName, fallthrough; EndpointSlices with core Endpoints fallback)

### Phase 3 — high value ✅
- [x] autopath hosts rewrite template view transfer acl k8s_external cancel bufsize

### Phase 4 — authoritative ✅
- [x] file auto secondary dnssec sign (ECDSA/Ed25519 keys; RSA needs OpenSSL)

### Phase 5 — operational / transport / backends ✅
- [x] pprof(partial) trace(partial: no exporter) nsid chaos header minimal timeouts metadata multisocket
- [x] tls, grpc (client), dnstap, tsig, dns64, any, local, erratic, geoip, on
- [x] etcd route53 azure clouddns
- [ ] kubernetai (external plugin, multi-cluster) — not started

### Phase 6 — release
- [x] Docs (README, architecture, plugin API, plugin status), example Corefiles, Containerfile (scratch)
- [x] Live smoke test on dev: file zone (wildcards, CNAME, delegation, glue), AXFR over TCP with view, hosts, rewrite→template, health/ready/metrics
- [x] v0.1.0 tagged 2026-08-29 (release binary 14.8 MB, 53 directives)
- [x] v0.1.1 (2026-08-30): plugin.cfg order fix for #1 (kubernetes before forward); release assets attached
- [x] Container image built with podman on dev: `localhost/stormcoredns:0.1.0` (scratch, musl static, 15.1 MB)
- [x] GitHub release v0.1.0 carries the image as a docker-archive tar (`stormcoredns-0.1.0-image.tar.gz`), the static binary and SHA256SUMS; assets are built into `/build/assets/stormcoredns` on dev
- [x] ~~Pushed to the mkube registry~~ — superseded: mkube retired 2026-08-27; delivery is the `coredns` golden (#2)
- [x] `deploy/kubernetes/coredns.yaml` + `docs/integration.md` for the stormcos integration (asked for by the owner 2026-08-30)
- [x] Runs against rustkube as the cluster DNS (stormcos 11.03, 2026-09-21: `kubernetes.default.svc.cluster.local` → 10.96.0.1)
- [ ] Test containers per the stormcos test standard (#5)
- [ ] trace exporter (OTLP/Zipkin), NSEC3 in `file`/`sign`, CDS/CDNSKEY in `sign`, `kubernetes multicluster`

### In progress — #3 docs from the code (2026-09-26)
- [x] README, docs/, CLAUDE.md and module docs rewritten from the code as it is now; delivery is the `coredns` golden built by stormcos stage mode (also closes #2: no mkube registry)
- [x] Every doc claim the code does not back filed as an issue (#6–#16)
- [ ] sc-build green, close #2 and #3

### Next — bugs found by the #3 audit
Cluster-DNS path first (stormcos runs `lameduck 5s` + `reload` + `loop`):
- [ ] #6 `/health` stuck 503 after a reload with lameduck
- [ ] #7 a failed reload stops automatic reloads
- [ ] #8 `:port` listeners IPv4-only after a reload
- [ ] #9 `loop` false positive → exit(1) when upstream > 2 s
- [ ] #14 kubernetes NXDOMAIN before sync; discovery/readiness edge cases
- [ ] #10 dnssec bogus NXDOMAIN NSEC, RRSIG cache expiry
- [ ] #11 secondary expire/retry/serial; task leaks on reload
- [ ] #12 view metadata(); #13 file wildcards/DNAME
- [ ] #15 CoreDNS divergences (verify each against 1.12 first); #16 dead hooks/ignored options
