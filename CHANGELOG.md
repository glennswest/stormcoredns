# Changelog

## [Unreleased]

### 2026-08-30
- **docs:** `docs/integration.md` (image, ports, probes, RBAC, rustkube API requirements, Cilium notes) and `deploy/kubernetes/coredns.yaml` drop-in manifest.
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
