# Changelog

## [Unreleased]

### 2026-08-29
- **feat:** Project scaffold — Cargo manifest, gitignore, changelog, work plan.
- **feat:** Corefile lexer/parser with `import`, snippets, `{$ENV}`; caddy-compatible `Dispenser`/`Controller`.
- **feat:** Plugin chain (`Handler`, `Next`, `Reply`, `PluginError`), registry in CoreDNS `plugin.cfg` order.
- **feat:** Servers: zone dispatch with views, UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, gRPC; SO_REUSEPORT binds; reload on Corefile change, SIGHUP, SIGUSR1.
- **feat:** Plugins: errors, log, bind, debug, root, whoami, forward, cache, health, ready, prometheus, loop, reload, loadbalance.
- **fix:** Unmap IPv4-mapped peer addresses so `family`/logs match CoreDNS.
