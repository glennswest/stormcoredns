# Plugin status

Every directive in CoreDNS 1.12's `plugin.cfg`, in chain order. "Full"
means the directive syntax and behaviour documented for CoreDNS are
implemented; notes list deliberate gaps.

| plugin | status | notes |
|---|---|---|
| root | full | |
| metadata | full | providers: `geoip` (others can implement `Handler::metadata`) |
| geoip | full | MaxMind City/Country, `edns-subnet` |
| cancel | full | wraps the chain in a timeout; SERVFAIL on expiry |
| tls | full | `client_auth` modes; serves tls://, https://, quic://, grpc:// |
| timeouts | full | read/write/idle for stream listeners |
| multisocket | full | SO_REUSEPORT sockets per address |
| reload | full | sha256 of the Corefile, interval + jitter, `coredns_reload_*` metrics |
| nsid | full | |
| bufsize | full | |
| bind | full | addresses, interface names, `except` |
| debug | full | |
| trace | partial | spans go to the `tracing` subscriber; no Zipkin/Datadog exporter |
| ready | full | plugins report via `Handler::ready` (kubernetes, route53, azure, clouddns) |
| health | full | lameduck keeps serving DNS while `/health` returns 503 |
| pprof | partial | `/debug/pprof/` serves process stats; no Go runtime profiles |
| prometheus | full | `coredns_*` names/labels, `plugin_enabled`, `build_info` |
| errors | full | `consolidate`, `stacktrace` |
| log | full | `common`, `combined`, custom formats, classes, `{/metadata}` |
| dnstap | full | Frame Streams to unix/tcp/tls, `full`, identity/version/extra |
| local | full | |
| dns64 | full | RFC 6052 prefixes /32–/96, `translate_all`, `allow_ipv4` |
| acl | full | allow/block/filter/drop by net and type |
| any | full | RFC 8482 |
| chaos | full | |
| loadbalance | full | round_robin and weighted (with reload) |
| tsig | full | verify requests, sign responses, `require`; HMAC-MD5/SHA1/SHA2 |
| cache | full | success/denial stores, prefetch, serve_stale (immediate/verify), servfail, disable, keepttl |
| rewrite | full | name (exact/prefix/suffix/substring/regex, answer auto/name/value), type, class, ttl, rcode, cname, edns0 local/nsid/subnet |
| header | full | |
| dnssec | full | online signing, black-lies NSEC, DNSKEY, signature cache; ECDSA P-256/P-384 and Ed25519 keys (BIND or PEM/PKCS#8) — no RSA |
| autopath | full | resolv.conf search path or `@kubernetes` (needs `pods verified`) |
| minimal | full | |
| template | full | `.Name .Zone .Class .Type .Remote .Message.Id`, `index .Match N`, `.Group.x`, `.Meta` |
| transfer | full | AXFR out (multi-message), IXFR falls back to AXFR, NOTIFY to `to` |
| hosts | full | file + inline, reload, `no_reverse`, fallthrough |
| file | full | wildcards, CNAME chase (external via self lookup), delegations + glue, ENT, NSEC/RRSIG/DS passthrough for signed zones; serial-based reload with NOTIFY |
| auto | full | directory scan with regexp origin template, reload |
| secondary | full | AXFR in, SOA refresh/retry, NOTIFY from primaries |
| etcd | full | SkyDNS layout: A/AAAA/CNAME/SRV/TXT/MX/PTR/NS/SOA, wildcards, credentials, tls, fallthrough |
| loop | full | |
| forward | full | udp/tcp/tls upstreams, health checks, random/round_robin/sequential, `except`, `force_tcp`, `prefer_udp`, `max_fails`, `max_concurrent`, `next`/`failover`, resolv.conf files, connection pool |
| grpc | full | tonic client, tls, policies |
| erratic | full | |
| whoami | full | |
| on | full | startup/shutdown commands, `&` |
| sign | full | NSEC chain + RRSIG + DNSKEY, CSK model, re-sign every 6d; no CDS/CDNSKEY output, no NSEC3 |
| view | full | expr language: `name() type() class() proto() size() port() id() opcode() do() bufsize() client_ip() server_ip() server_port() metadata() incidr()`, `in matches contains startsWith endsWith and or not` |
| kubernetes | full | Services, headless, endpoints by hostname/pod name/dashed IP, SRV (`_port._proto`), pods insecure/verified, PTR, ExternalName (CNAME chased), `namespaces`, `namespace_labels`, `labels`, `ttl`, `noendpoints`, `fallthrough`, `ignore empty_service`, `endpoint`/`tls`/`kubeconfig`; EndpointSlices with core Endpoints fallback. No `multicluster` |
| k8s_external | full | LoadBalancer/externalIPs, hostnames as CNAME, SRV, `headless`, PTR, `apex`, `ttl` |
| clouddns | full | service account JSON or GCE metadata; `PROJECT:ZONE[:ORIGIN]` |
| azure | full | public and private zones, all record types, three clouds |
| route53 | full | SigV4, static/profile/env credentials, alias → CNAME, pagination |

Handled by the parser rather than a plugin: `import` (files, globs,
snippets).
