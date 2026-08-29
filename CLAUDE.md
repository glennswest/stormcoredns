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

### Phase 1 — core (in progress)
- [x] Cargo manifest, gitignore, changelog
- [ ] Corefile lexer/parser/Dispenser (import, snippets, env vars, blocks)
- [ ] Plugin trait, chain, request/reply, registry, plugin.cfg order
- [ ] Server: config from server blocks, zone dispatch, UDP+TCP listeners
- [ ] TLS, DoH, DoQ, gRPC transports
- [ ] main.rs CLI matching `coredns` flags
- [ ] Core plugins: whoami, log, errors, hosts, file, forward, cache, rewrite,
      template, health, ready, prometheus, bind, root, reload, debug
- [ ] Build + test on dev, tag v0.1.0

### Phase 2 — remaining plugins
- [ ] acl any autopath bufsize cancel chaos dns64 dnssec dnstap erratic geoip
      grpc header k8s_external kubernetes loadbalance local loop metadata
      minimal multisocket nsid on pprof secondary sign timeouts tls trace
      transfer tsig view auto etcd
- [ ] Cloud: route53 azure clouddns

### Phase 3
- [ ] Container image (scratch base, podman), example Corefiles, integration tests
