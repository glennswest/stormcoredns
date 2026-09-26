# Changelog

## [Unreleased]

### 2026-09-26 (#4)
- **docs:** `docs/presentation.md` — a 14-slide Marp deck: purpose, place in stormcos (with the real runtime dependencies; stormcentral#35 corrects the graph), how it works, what the kubernetes plugin serves, the plugin set and transports, CLI/config/health/metrics, how it ships (the `coredns` golden) and is operated, gaps, planned work, and the open issues that matter. Rendered output (`out/`, `docs/presentation.{html,pdf}`) is git-ignored.

### 2026-09-26
- **docs:** README, `docs/integration.md`, `docs/plugins.md`, `docs/architecture.md`, `docs/plugin-api.md` and CLAUDE.md rewritten from the code (#3): every flag, env var, key scheme and default port; health/ready/metrics/pprof endpoints and defaults; full metric list; per-plugin status now says `partial`/`differs` where the code does, with the issues it links.
- **docs:** Delivery is the `coredns` golden built by stormcos stage mode (`stormcentral component stage coredns`); the retired mkube registry is gone from the docs and the non-stormcos manifest (#2).
- **docs:** Module comments corrected (Dispenser, `Instance::start`/`stop`, `wire`, `transfer` data sources, `template` regex case, CLI flags).
- **chore:** Filed the gaps the audit found: #6–#16.

## [v0.1.1] — 2026-08-30

### Fixed
- Plugin chain order now matches CoreDNS `plugin.cfg`: `route53`, `azure`, `clouddns`, `k8s_external`, `kubernetes` run after `hosts` and before `file`/`auto`/`secondary`/`etcd`/`loop`/`forward`. Previously `forward .` answered every `cluster.local` query with upstream NXDOMAIN (#1). A test pins the order.

### 2026-08-30
- **docs:** `docs/integration.md` (image, ports, probes, RBAC, rustkube API requirements, Cilium notes) and `deploy/kubernetes/coredns.yaml` drop-in manifest.
- **chore:** GitHub release v0.1.0 with the container image as a tar (`docker-archive`), the static binary and checksums.
- **chore:** Image published to the local registry `192.168.200.3:5000/stormcoredns:0.1.0` / `:latest`.

## [v0.1.0] — 2026-08-29

### Added
- Corefile lexer/parser with `import`, snippets, `{$ENV}`; caddy-compatible `Dispenser`/`Controller`.
- Plugin chain (`Handler`, `Next`, `Reply`, `PluginError`), registry in CoreDNS `plugin.cfg` order, cross-plugin hooks (`ready`, `autopath`, `transfer`, `external_addrs`, `metadata`) and deferred wiring.
- Servers: zone dispatch with views, UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, gRPC; SO_REUSEPORT binds; multi-message replies for zone transfers; reload on Corefile change, SIGHUP, SIGUSR1; `-pidfile`.
- Cluster DNS: kubernetes (Services, headless endpoints, SRV, pods insecure/verified, PTR, ExternalName, `fallthrough`, `ignore empty_service`, EndpointSlices with core Endpoints fallback), k8s_external, autopath, forward, cache, loop, loadbalance, reload, health, ready, prometheus, errors.
- Query/answer plugins: rewrite, template, hosts, acl, view (expr language), cancel, bufsize, dns64, any, local, minimal, header, nsid, chaos, whoami, erratic.
- Authoritative: zone engine (wildcards, CNAME chase, delegations with glue, empty non-terminals, NSEC/RRSIG passthrough), file, auto, secondary, transfer (AXFR/IXFR out, NOTIFY), dnssec (online signing, black-lies NSEC), sign (offline NSEC+RRSIG), tsig.
- Server/operational: bind, tls, timeouts, multisocket, root, debug, metadata, geoip, on, log, dnstap, trace, pprof.
- Backends: etcd (SkyDNS layout), grpc, route53 (SigV4), azure, clouddns.
- `coredns_*` Prometheus metrics with CoreDNS names and labels.

### Fixed
- IPv4-mapped peer addresses are unmapped so `family`/logs match CoreDNS.

### Documentation
- README, architecture, plugin API, plugin status table, example Corefiles (kubernetes, authoritative, smoke), Containerfile (scratch base).
