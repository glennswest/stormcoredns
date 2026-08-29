# Changelog

## [Unreleased]

### 2026-08-29
- **feat:** Project scaffold — Cargo manifest, gitignore, changelog, work plan.
- **feat:** Corefile lexer/parser with `import`, snippets, `{$ENV}`; caddy-compatible `Dispenser`/`Controller`.
- **feat:** Plugin chain (`Handler`, `Next`, `Reply`, `PluginError`), registry in CoreDNS `plugin.cfg` order.
- **feat:** Servers: zone dispatch with views, UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, gRPC; SO_REUSEPORT binds; reload on Corefile change, SIGHUP, SIGUSR1.
- **feat:** Plugins: errors, log, bind, debug, root, whoami, forward, cache, health, ready, prometheus, loop, reload, loadbalance.
- **fix:** Unmap IPv4-mapped peer addresses so `family`/logs match CoreDNS.
- **feat:** kubernetes plugin: Services, headless endpoints, SRV, pods (insecure/verified), PTR, ExternalName (CNAME chased in-process), `fallthrough`, `ignore empty_service`, EndpointSlices with core Endpoints fallback; readiness once watches sync.
- **feat:** Plugins: cancel, bufsize, acl (allow/block/filter/drop), hosts, autopath (`@kubernetes` and resolv.conf), k8s_external, transfer (AXFR/IXFR out, NOTIFY), view (expr language), rewrite (name/type/class/ttl/rcode/cname/edns0), template.
- **feat:** `Reply::Drop` and `Reply::Multi` (multi-message zone transfers over TCP); cross-plugin hooks (`autopath`, `transfer`, `external_addrs`, `metadata`) and deferred wiring.
- **feat:** Plugins: nsid, chaos, header, minimal, timeouts, metadata, multisocket, any, local, erratic, tls.
- **feat:** Zone engine (wildcards, CNAME chase, delegations with glue, empty non-terminals, NSEC/RRSIG passthrough); file, auto, secondary plugins.
- **feat:** dnssec (online signing, black-lies NSEC, signature cache), sign (offline NSEC+RRSIG zone signing), tsig, dns64, geoip, on, pprof, trace, dnstap, grpc.
- **feat:** Backends: etcd (SkyDNS layout), route53 (SigV4), azure (public/private zones), clouddns (service account / metadata).
- **docs:** README, architecture, plugin API, plugin status table, example Corefiles, Containerfile.
