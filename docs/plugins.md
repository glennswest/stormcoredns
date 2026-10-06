# Plugin status

This covers every directive in CoreDNS 1.12's `plugin.cfg`, in chain order
(`src/plugin/registry.rs`). The status and notes come from reading the code
as of 2026-09-26 (#3).

- **full**: the documented CoreDNS syntax is accepted and behaves as it does
  in CoreDNS, apart from the notes.
- **partial**: something documented for CoreDNS is missing or ignored.
- **differs**: complete, but a default or a behaviour does not match CoreDNS.

Bugs are linked by issue number. #15 collects the CoreDNS differences and #16
the options that are accepted but ignored.

| plugin | status | defaults and notes |
|---|---|---|
| root | full | `root PATH`, once per block. A missing directory only warns. The default is the Corefile's directory |
| metadata | full | Providers are plugins that implement `Handler::metadata`. Only `geoip` does today, so there are no `kubernetes/*` labels |
| geoip | full | MaxMind City/Country databases (no ASN) and `edns-subnet`. Labels: `geoip/city/name`, `geoip/country/{code,name,is_in_european_union}`, `geoip/continent/{code,name}`, `geoip/latitude`, `geoip/longitude`, `geoip/timezone`, `geoip/postalcode` |
| cancel | full | Default 5001 ms. The chain runs under a timeout, and on expiry the query gets SERVFAIL |
| tls | differs | `tls CERT KEY [CA] { client_auth … }`. Because of rustls, `request` behaves as `verify_if_given` and `require` as `require_and_verify`, and every mode except `nocert` needs a CA. Serves tls://, https://, quic:// and grpc:// |
| timeouts | partial | `read`/`write`/`idle` (1s–24h). Defaults are 2s/2s/10s. They apply to TCP, DoT and DoQ; **DoH and gRPC ignore them** |
| multisocket | full | Default is the CPU count, with no upper bound. SO_REUSEPORT is set on every socket either way |
| reload | full | Default 30s interval, 15s jitter (minimum 2s/1s). The Corefile's SHA-256 is checked every 15–30 s, and `reload_version_info{hash="sha256"}`. Bugs: #6, #7 |
| nsid | full | Default is the hostname |
| bufsize | differs | 512–4096; **default 512** (CoreDNS uses 1232) |
| bind | full | Addresses and interface names (getifaddrs), plus `except`. An interface also yields its IPv6 link-local addresses, which have no scope ID |
| debug | partial | Accepted and ignored. Panic recovery is always on (a panic returns SERVFAIL and increments `coredns_panics_total`) |
| trace | partial | Spans go to the `tracing` subscriber. There is no Zipkin or Datadog exporter: the endpoint and type are only logged, and the batch/backlog options are ignored |
| ready | full | Default `:8181`, `GET /ready`. Readiness is re-checked on every request. Plugins that report it: kubernetes, route53, azure, clouddns |
| health | full | Default `:8080`, `/health`, `lameduck` defaults to 0. It probes itself every second to feed `coredns_health_*`. Bug: #6 |
| pprof | partial | Default `localhost:6053`. `/debug/pprof/` serves process statistics (stats, heap, allocs, threads) as text, not Go profiles; other profiles return 501. `block` is ignored |
| prometheus | full | Default `localhost:9153`, `/metrics`. See [Metrics](#metrics). There are no `process_*` metrics |
| errors | full | `stdout`, `stacktrace`, `consolidate DUR REGEXP [level]`. `stacktrace` records the errors plugin's own stack, not the origin of the error |
| log | full | `common`, `combined`, custom formats with `{…}`, `class`, and `{/label}` metadata. Written with `println!` |
| dnstap | partial | `unix://`, `tcp://IP:port` or `tls://IP:port` (default port 6000), plus `full`, `identity`, `version`, `extra`, `skipverify`. **Only CLIENT_QUERY and CLIENT_RESPONSE are sent, with no FORWARDER messages.** When the 10k queue is full, messages are dropped silently |
| local | partial | `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, and the 127/8 and ::1 reverse names. Missing: `0.`/`255.in-addr.arpa`, the `::` reverse name, `localhost.<domain>`, and the requests metric |
| dns64 | differs | Prefix `/32`–`/96`, default `64:ff9b::/96`; `translate_all`, `allow_ipv4`. It also synthesizes on NXDOMAIN (RFC 6147 says not to) |
| acl | differs | `allow`/`block`/`filter`/`drop`, each with optional `type` and `net`. When no policy in a zone-matching rule matches, the query is allowed; CoreDNS moves on to the next rule. No EDE |
| any | full | RFC 8482 HINFO, TTL 8482 |
| chaos | full | Default version `CoreDNS-1.12 (stormcoredns-X)`. Authors are sorted and de-duplicated |
| loadbalance | full | `round_robin` (A/AAAA/MX in the answer and additional sections), or `weighted FILE { reload 30s }`. The weighted reload task leaks across reloads (#11) |
| tsig | partial | `secret NAME KEY` (always HMAC-SHA256), `secrets FILE`, `require all\|none\|TYPES`. Unsigned when required → REFUSED; a bad key or signature → NOTAUTH. **AXFR replies are not signed** |
| cache | differs | Default capacity 9984 per store, max TTL 3600 (success) and 1800 (denial), min TTL 5. `prefetch` (60s window, 10%), `serve_stale` (1h, immediate\|verify), `servfail`, `disable`, `keepttl`. **SERVFAIL is not cached unless `servfail` is set** (CoreDNS caches it for 5s). The cache key has no qclass |
| rewrite | full | `name` (exact/prefix/suffix/substring/regex, `answer auto\|name\|value`), `type`, `class`, `ttl`, `rcode`, `cname`, `edns0 local\|nsid\|subnet`; `stop` is the default. `answer auto` does not invert a regex. `ttl` clamps only answers whose owner matches |
| header | full | `query\|response set\|clear` for aa ra rd ad cd tc |
| dnssec | partial | Online signing, black-lie NSEC, DNSKEY, and a signature cache (default 10000). Keys: ECDSA P-256/P-384 and Ed25519 in BIND or PEM/PKCS#8 format; **no RSA**. KSK/ZSK flags are ignored (every key signs). Bugs: #10 |
| autopath | full | `RESOLV-CONF`, `@kubernetes` (needs `pods verified`) or `@erratic` |
| minimal | full | Strips the authority and additional sections (keeping OPT) on a NOERROR reply that has answers |
| template | differs | `.Name .Question.Name .Zone .Class .Type .Remote .Message.Id`, `index .Match N`, `.Group.x`, `.Meta "l"`; no functions or pipelines. On a regex miss, the query goes to the next plugin even without `fallthrough`. `ederror` and `upstream` are ignored. Default TTL 3600 |
| transfer | full | `to IP[:port]\|*`. AXFR out is split into ~60 KB messages over TCP/DoT (DoH, DoQ and gRPC send only the first message). IXFR returns SOA-only when the serials are equal, otherwise a full transfer. NOTIFY to each `to` IP is a single UDP packet with no retry |
| hosts | differs | Default `/etc/hosts`, TTL 3600, reload 5s (mtime); inline entries, `no_reverse`, `fallthrough`. An unknown name gets NXDOMAIN without an SOA. `fallthrough` also applies when the name exists with a different type |
| file | partial | `reload` default 60s: the file is polled by mtime and reloaded when the serial changes, and NOTIFY is sent. Wildcards, CNAME chase (external targets resolved through the server itself, max 8 hops), delegations with glue, empty non-terminals, and NSEC/RRSIG/DS passthrough for signed zones. **No DNAME, no NSEC3 proofs.** Bugs: #13 |
| auto | full | `directory DIR [REGEXP TEMPLATE]` (default `db\.(.*)` → `{1}`), `reload` 60s. Every file is re-parsed on every tick |
| secondary | partial | `transfer from IP…`. AXFR in over TCP (no IXFR, no TSIG) and SOA polling. NOTIFY is accepted from primaries only. Queries get SERVFAIL until the first transfer. **SOA expire is ignored**; see #11 |
| etcd | differs | SkyDNS layout (default path `/skydns`, endpoint `http://localhost:2379`): A/AAAA/CNAME/SRV/TXT/MX/PTR/NS/SOA, wildcards, `credentials`, `tls`, `fallthrough`. `upstream`/`stubzones` are ignored. Default TTL 30 |
| loop | full | A UDP probe to the first bind address, for the first zone, active for about 30 s after startup. Up to 3 attempts (2 s each), each with its own random name, so a slow or unreachable upstream is never taken for a loop; a loop is one probe name arriving more than twice, as in CoreDNS (#18, #9) |
| forward | full | `dns://` and `tls://` IP upstreams (at most 15 unless `sequential`). Policy `random` by default, also `round_robin`/`sequential`. `max_fails` 2, `expire` 10s, `health_check` 500ms (runs only after a failure), plus `except`, `force_tcp`, `prefer_udp`, `tls`, `tls_servername`, `max_concurrent` (over the limit → REFUSED), `next`, `failover`. There is a TCP/TLS connection pool (64 per upstream), and UDP opens a new socket per query. Timeouts: 5s each for dial, read and overall. `next` behaves like `failover` (#15) |
| grpc | full | tonic client, `tls`, `tls_servername`, `policy`, `except`; 5s timeout; no health checks |
| erratic | full | `drop`, `truncate` and `delay` (default every 2nd query, 100 ms), `large`. AXFR gets AAAA records |
| whoami | differs | A/AAAA plus SRV. The SRV owner is `_<port>._<proto>.<qname>` with the qname as target; CoreDNS uses `_<proto>.<qname>` with target `.` |
| on | full | `startup`/`shutdown` commands, `&`. Every command is spawned without waiting |
| sign | partial | Offline NSEC chain, RRSIG and DNSKEY (CSK: every key signs everything), written to `db.<origin>.signed` in `directory` (default `/var/lib/coredns`). Signatures last 32 days. Re-signs when the source changes, or every ~6 days measured from process start. **No NSEC3, no CDS/CDNSKEY**; `key directory` only picks up `K*.key` |
| view | partial | Language: `name() type() class() proto() size() port() id() opcode() do() bufsize() client_ip() server_ip() server_port() incidr()`, `in matches contains startsWith endsWith`, comparisons, arithmetic, `and or not`/`&& \|\| !`. Several `expr` lines are ANDed. **`metadata()` is always empty** (#12) |
| kubernetes | full | `endpoint`, `tls`, `kubeconfig`, `namespaces`, `namespace_labels`, `labels`, `pods disabled\|insecure\|verified` (default disabled), `endpoint_pod_names`, `ttl` (default 5), `noendpoints`, `fallthrough`, `ignore empty_service`. EndpointSlices, falling back to core Endpoints. `multicluster` is rejected. See [integration.md](integration.md) and #14 |
| k8s_external | full | LoadBalancer ingress and externalIPs, hostnames as CNAME, SRV, `headless` (endpoint IPs merged into the service name; no per-endpoint names), PTR, `apex` (default `dns`), `ttl` (default 5), `fallthrough` |
| clouddns | differs | `clouddns PROJECT:ZONE[:ORIGIN]` (not CoreDNS's argument order), `credentials FILE` or `GOOGLE_APPLICATION_CREDENTIALS` or the GCE metadata server, `fallthrough`. Refresh every 60s |
| azure | full | `tenant`, `client`, `secret`, `subscription` (or `AZURE_*`), `environment` (public, US Gov or China cloud), `access public\|private`, `fallthrough`. Refresh every 60s. The private-zone field casing is unverified (#15) |
| route53 | full | SigV4 (region us-east-1). Credentials from `aws_access_key`, `credentials PROFILE [FILE]` or `AWS_*` env (no IMDS/IRSA). Alias records become a CNAME with TTL 60. `refresh` 60s, with pagination |

The parser handles `import` (files, globs, snippets), not a plugin. It only
works inside a server block.

## Metrics

All metric names are `coredns_*`, served from one registry (no `process_*` or
`go_*` metrics).

- **core** (`src/metrics.rs`, counted by the `prometheus` plugin):
  - `dns_requests_total`, `dns_request_duration_seconds`,
    `dns_request_size_bytes`, `dns_do_requests_total`,
    `dns_response_size_bytes`, `dns_responses_total`;
  - `dns_https_responses_total` and `dns_quic_responses_total` (not in
    upstream);
  - `panics_total`, `plugin_enabled`, `build_info` (revision is the git SHA,
    goversion is `rust`);
  - `health_request_duration_seconds`, `health_request_failures_total`,
    `reload_failed_total`, `reload_version_info`.
- **cache**: `cache_entries`, `cache_hits_total`, `cache_misses_total`,
  `cache_requests_total`, `cache_drops_total`, `cache_evictions_total`,
  `cache_prefetch_total`, `cache_served_stale_total`.
- **forward**: `forward_requests_total`, `forward_responses_total`,
  `forward_request_duration_seconds`, `forward_healthcheck_failures_total`,
  `forward_healthcheck_broken_total`, `forward_max_concurrent_rejects_total`,
  `forward_conn_cache_hits_total`, `forward_conn_cache_misses_total`.
- **grpc**: `grpc_requests_total`, `grpc_responses_total`,
  `grpc_request_duration_seconds`.
- **kubernetes**: `kubernetes_dns_programming_duration_seconds`.
- **acl**: `acl_{allowed,blocked,filtered,dropped}_requests_total`.
- **template**: `template_matches_total`, `template_template_failures_total`,
  `template_rr_failures_total`.
- **dnssec**: `dnssec_cache_entries`, `dnssec_cache_hits_total`,
  `dnssec_cache_misses_total`.
- **hosts**: `hosts_entries`, `hosts_reload_timestamp_seconds`.
- **others**: `dns64_requests_translated_total`, `autopath_success_total`.
