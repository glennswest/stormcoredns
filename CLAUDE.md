# CLAUDE.md — stormcoredns

A Rust reimplementation of [CoreDNS](https://coredns.io): same Corefile
syntax, same plugin-chain model, same plugin names and directives, same
external APIs (DNS over UDP/TCP/TLS/HTTPS/QUIC/gRPC, Prometheus metrics,
`/health`, `/ready`, dnstap, reload). Design notes are in
[docs/architecture.md](docs/architecture.md); the plugin authoring contract
is [docs/plugin-api.md](docs/plugin-api.md); per-plugin status is in
[docs/plugins.md](docs/plugins.md).

## Version

`0.1.0` — defined in `Cargo.toml` only (`src/main.rs` reads
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

### Phase 4 — authoritative
- [ ] file auto secondary dnssec sign

### Phase 5 — operational / transport / backends
- [ ] pprof trace nsid chaos header minimal timeouts metadata multisocket
- [ ] tls (server-side config), grpc (client), dnstap, tsig, dns64, any, local, erratic, geoip, on
- [ ] etcd route53 azure clouddns kubernetai

### Phase 6
- [ ] Container image (scratch base, podman), example Corefiles, integration tests, v0.1.0 tag
