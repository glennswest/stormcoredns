# stormcoredns

CoreDNS, reimplemented in Rust. Same Corefile, same plugin names and
directives, same chain order, same external APIs — so an existing
kube-dns ConfigMap, a `forward`/`cache` resolver Corefile, or an
authoritative `file`/`transfer` setup runs unchanged.

```text
.:53 {
    errors
    health { lameduck 5s }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf { max_concurrent 1000 }
    cache 30
    loop
    reload
    loadbalance
}
```

```bash
stormcoredns -conf Corefile          # same flags as coredns
stormcoredns -dns.port 1053 -quiet
stormcoredns -plugins                # list the 53 directives
```

## What is implemented

Every directive in CoreDNS 1.12's `plugin.cfg` is recognised and served by
this binary (see [docs/plugins.md](docs/plugins.md) for per-plugin detail
and the few documented gaps):

| area | plugins |
|---|---|
| cluster DNS | `kubernetes` `k8s_external` `autopath` `forward` `cache` `loop` `loadbalance` `reload` `health` `ready` `prometheus` `errors` |
| queries & answers | `rewrite` `template` `hosts` `acl` `view` `cancel` `bufsize` `dns64` `any` `local` `minimal` `header` `nsid` `chaos` `whoami` `erratic` |
| authoritative | `file` `auto` `secondary` `transfer` `dnssec` `sign` `tsig` |
| server | `bind` `tls` `timeouts` `multisocket` `root` `debug` `metadata` `geoip` `on` `log` `dnstap` `trace` `pprof` |
| backends | `etcd` `grpc` `route53` `azure` `clouddns` |

Transports: DNS over UDP and TCP, DNS-over-TLS (`tls://`), DNS-over-HTTPS
(`https://`), DNS-over-QUIC (`quic://`) and the CoreDNS gRPC protocol
(`grpc://`), all selected by the server-block key exactly as in CoreDNS.

APIs: Prometheus metrics with the `coredns_*` names and labels, `/health`,
`/ready`, `/debug/pprof/`, dnstap over Frame Streams, Corefile reload on
change / `SIGHUP` / `SIGUSR1`, `-pidfile`.

## Building

This is a Linux server; build it on Linux. The release profile is a
single static binary with LTO:

```bash
cargo build --release          # needs protoc for the gRPC service
./target/release/stormcoredns -conf examples/Corefile.kubernetes
```

Published image: `192.168.200.3:5000/stormcoredns:0.1.0` (local mkube registry); a drop-in cluster manifest is in
`deploy/kubernetes/coredns.yaml` and the integration notes in
[docs/integration.md](docs/integration.md). The image is built `FROM scratch`:

```bash
podman build -t stormcoredns:latest .
```

## Layout

```text
src/corefile/     Caddyfile-v1 lexer, parser (import, snippets, {$ENV}), Dispenser
src/plugin/       Handler trait, chain, Request/Reply, registry (plugin.cfg order), replacer
src/server/       zone dispatch + views, UDP/TCP/TLS/DoH/DoQ/gRPC listeners, reload
src/plugins/      one module per plugin, named after its directive
src/dnsutil/      names, reverse zones, upstream parsing, EDNS0, durations
docs/             architecture, plugin API, plugin status
examples/         Corefiles and a zone file
```

## Differences from CoreDNS you may notice

* `dnssec`/`sign` support ECDSA P-256/P-384 and Ed25519 keys (RSA needs
  OpenSSL, which this build does not link).
* `trace` emits spans to the `tracing` subscriber; there is no Zipkin/
  Datadog exporter yet.
* `pprof` serves process statistics under `/debug/pprof/` instead of Go
  runtime profiles.
* `multicluster` in `kubernetes` is not supported.

## License

Apache-2.0.
