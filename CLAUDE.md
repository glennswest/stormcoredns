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

## Build on dev, never on this Mac

Every `cargo build`/`test`/`check` runs on `root@dev.g8.lo`:

```bash
git push
ssh root@dev.g8.lo 'cd /root/stormcoredns && git pull -q && \
  CARGO_TARGET_DIR=/build/cargo/stormcoredns cargo build --release 2>&1 | tail -30'
ssh root@dev.g8.lo 'cd /root/stormcoredns && \
  CARGO_TARGET_DIR=/build/cargo/stormcoredns cargo test 2>&1 | tail -30'
```

Target dir is `/build/cargo/stormcoredns` (spinning drive, never the SSD).
Never write images or large files to `/tmp` on dev (tmpfs).

## Layout

```
src/main.rs            CLI (clap): -conf, -dns.port, -p, -pidfile, -quiet, -version, -plugins
src/corefile/          Caddyfile-v1 lexer + parser + Dispenser/Controller (import, snippets, {$ENV})
src/plugin/            Handler trait, chain, Request, Reply, PluginError, registry, plugin.cfg order
src/server/            listener grouping, UDP/TCP/TLS/DoH/DoQ/gRPC servers, zone dispatch, views
src/plugins/<name>.rs  one module per CoreDNS plugin, same name as upstream
src/dnsutil/           name helpers, reverse zones, response builders, EDNS0 helpers
src/metrics.rs         global Prometheus registry + core metrics
docs/                  architecture, plugin API, per-plugin docs
examples/              Corefiles
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
- [x] v0.1.1 (2026-08-30): plugin.cfg order fix for #1 (kubernetes before forward); image 0.1.1 in the local registry, release assets attached
- [x] Container image built with podman on dev: `localhost/stormcoredns:0.1.0` (scratch, musl static, 15.1 MB)
- [x] GitHub release v0.1.0 carries the image as a docker-archive tar (`stormcoredns-0.1.0-image.tar.gz`), the static binary and SHA256SUMS; assets are built into `/build/assets/stormcoredns` on dev
- [x] Pushed `192.168.200.3:5000/stormcoredns:0.1.0` and `:latest` (2026-08-30, `podman push --tls-verify=false`). GHCR is not used.
- [x] `deploy/kubernetes/coredns.yaml` + `docs/integration.md` for the stormcos integration (asked for by the owner 2026-08-30)
- [ ] Run against a real rustkube/Kubernetes cluster (kubernetes plugin end-to-end)
- [ ] trace exporter (OTLP/Zipkin), NSEC3 in `file`/`sign`, CDS/CDNSKEY in `sign`, `kubernetes multicluster`
