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
docs/                  architecture, plugin API, per-plugin status + metrics, stormcos integration, presentation.md (Marp)
examples/              Corefiles + a zone file
test/                  stormcoredns-test: the test container (/test short|medium|long, test/README.md); workspace member, not in the golden build
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
- [ ] Test containers per the stormcos test standard (#5) — built; first in-cluster run pending (see below)
- [ ] trace exporter (OTLP/Zipkin), NSEC3 in `file`/`sign`, CDS/CDNSKEY in `sign`, `kubernetes multicluster`

### Done — #3 docs from the code (2026-09-26)
- [x] README, docs/, CLAUDE.md and module docs rewritten from the code as it is now; delivery is the `coredns` golden built by stormcos stage mode (also closes #2: no mkube registry)
- [x] Every doc claim the code does not back filed as an issue (#6–#16)
- [x] sc-build green (de6be9a, 54 tests), #2 and #3 closed

### Done — #4 presentation (2026-09-26)
- [x] `docs/presentation.md`: Marp deck (14 slides) drawn from the #3 docs, every claim checkable against the code; renders with `npx @marp-team/marp-cli@4`
- [x] stormcentral's graph has `stormcoredns depends_on stormd`, but the `coredns` golden is a bare binary (no stormd) — filed stormcentral#35; the slide shows the real runtime dependencies

### In progress — #5 test containers (2026-09-27)
Design (stormcentral `docs/test-standard.md`, runner `src/testruns.rs`):
the runner applies its own Job (`/test <suite>`, plain pod, SA `storm-test`
with `*` in the run's namespace only, no cluster read). So the test finds the
cluster DNS from its own `/etc/resolv.conf` (nameserver + `<ns>.svc.<domain>`
search, written by rustkube-node's kubelet) and checks it against Services,
Endpoints and EndpointSlices it creates in its own namespace.
- [x] `test/` crate `stormcoredns-test` (workspace member; tokio, hickory-proto, reqwest, serde_json, anyhow — already in Cargo.lock; lock entry hand-added, verified by `--locked`), `test/build.sh`, `test/Containerfile` (scratch), `test/README.md` with metadata
- [x] short: SOA at the apex, Service A over UDP+TCP, SRV, NXDOMAIN+SOA, delete → NXDOMAIN
- [x] medium: headless A/SRV/hostnames, PTR, ExternalName, pods, dns-version, endpoint change, UDP truncation vs TCP/EDNS, FORMERR, forward path, case, concurrency
- [x] long: waves of Services ramped until the cluster pushes back; programming latency, query p50/p99, drain residue, probe slowdown vs wave 1
- [x] sc-build `cargo build --locked --workspace && cargo test --locked --workspace && STAGE_ONLY=1 test/build.sh` green (491a7af; 3.4 MB static binary)
- [ ] **Blocked:** first real run. stormcentral#56 is fixed (20a570b) and C2NR0Q2's apiserver now answers, but run 54b2f2032b (2026-09-27, 4695f5d) stopped at the image step: C2NR0Q2's sbregistry refuses connections on :5100 (same for every component's run) — filed stormcentral#71. When it is fixed: `stormcentral test run stormcoredns short|medium --tag C2NR0Q2 --url http://stormcentral.g8.lo`, fix what it finds, then close #5.

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
