# Plugin status

This covers every directive in CoreDNS 1.12's `plugin.cfg`, in chain order
(`src/plugin/registry.rs`). The status and notes come from reading the code
as of 2026-09-26 (#3).

- **full**: the documented CoreDNS syntax is accepted and behaves as it does
  in CoreDNS, apart from the notes.
- **partial**: something documented for CoreDNS is missing or ignored.
- **differs**: complete, but a default or a behaviour does not match CoreDNS.

Bugs are linked by issue number. The CoreDNS differences found by the docs
audit were checked against CoreDNS v1.12.4's source and fixed in #15; what is
left is tracked in #21–#24. #16 covered the options that are accepted but ignored.

| plugin | status | defaults and notes |
|---|---|---|
| root | full | `root PATH`, once per block. A missing directory only warns. The default is the Corefile's directory |
| metadata | full | Providers are plugins that implement `Handler::metadata`. Only `geoip` does today, so there are no `kubernetes/*` labels |
| geoip | full | MaxMind City/Country databases (no ASN) and `edns-subnet`. Labels: `geoip/city/name`, `geoip/country/{code,name,is_in_european_union}`, `geoip/continent/{code,name}`, `geoip/latitude`, `geoip/longitude`, `geoip/timezone`, `geoip/postalcode` |
| cancel | full | Default 5001 ms. The chain runs under a timeout, and on expiry the query gets SERVFAIL. The deadline is also `req.deadline`: `forward` stops trying upstreams once it passes |
| tls | full | `tls CERT KEY [CA] { client_auth … }`, as Go's `tls.ClientAuthType`: `request`/`require` take any client certificate unverified, `verify_if_given`/`require_and_verify` verify against the CA (or the system roots without one). Serves tls://, https://, quic:// and grpc:// |
| timeouts | full | `read`/`write`/`idle` (1s–24h). Defaults 3s/5s/10s, as in CoreDNS. TCP, DoT and DoQ; DoH applies read to the TLS handshake and request body, write to producing the answer, idle between requests. gRPC ignores them, as in CoreDNS |
| multisocket | full | Default is the CPU count, with no upper bound. SO_REUSEPORT is set on every socket either way |
| reload | full | Default 30s interval, 15s jitter (minimum 2s/1s). The parsed Corefile (imports expanded) is hashed with SHA-512 every 15–30 s, as in CoreDNS; an edit that does not parse is skipped. `reload_version_info{hash="sha512"}`. Bugs: #6, #7 |
| nsid | full | Default is the hostname |
| bufsize | full | 512–4096; default 1232 |
| bind | full | Addresses and interface names (getifaddrs), plus `except`. An interface also yields its IPv6 link-local addresses, which have no scope ID |
| debug | full | Turns panic recovery off for the server block: a panic while serving is logged and the process exits (status 2), as an unrecovered Go panic does. Without it a panic returns SERVFAIL and increments `coredns_panics_total`. Log levels come from `STORMCOREDNS_LOG`/`RUST_LOG` |
| trace | partial | Spans go to the `tracing` subscriber. There is no Zipkin or Datadog exporter: the endpoint and type are logged as unused, and the batch/backlog/analytics options are ignored with a warning |
| ready | full | Default `:8181`, `GET /ready`. Readiness is re-checked on every request. Plugins that report it: kubernetes, route53, azure, clouddns |
| health | full | Default `:8080`, `/health`, `lameduck` defaults to 0. It probes itself every second to feed `coredns_health_*`. Bug: #6 |
| pprof | partial | Default `localhost:6053`. `/debug/pprof/` serves process statistics (stats, heap, allocs, threads) as text, not Go profiles; other profiles return 501. `block` is ignored with a warning |
| prometheus | full | Default `localhost:9153`, `/metrics`. See [Metrics](#metrics). `process_*` metrics are read from `/proc/self`; there are no `go_*` metrics |
| errors | full | `stdout`, `stacktrace`, `consolidate DUR REGEXP [level]`. `stacktrace` records the errors plugin's own stack, not the origin of the error |
| log | full | `common`, `combined`, custom formats with `{…}`, `class`, and `{/label}` metadata. Written with `println!` |
| dnstap | partial | `unix://`, `tcp://host:port` or `tls://host:port` (default port 6000), plus `full`, `identity`, `version`, `extra`, `skipverify`. **Only CLIENT_QUERY and CLIENT_RESPONSE are sent; `forward` sends no FORWARDER messages (#22).** When the 10k queue is full, messages are dropped and the count is logged every second, as in CoreDNS |
| local | full | A port of CoreDNS's plugin: `localhost.` (A/AAAA/SOA/NS), `localhost.<anything>` (127.0.0.1/::1, counted in `local_localhost_requests_total`), the `0.`, `127.` and `255.in-addr.arpa.` zones (`1.0.0.127.in-addr.arpa` PTR `localhost.`), NXDOMAIN with the zone's SOA for the rest. Like CoreDNS, it does not answer `ip6-localhost` or `::1`'s reverse name |
| dns64 | full | Prefix `/32`–`/96`, default `64:ff9b::/96`; `translate_all`, `allow_ipv4`. NXDOMAIN is returned unchanged (RFC 6147 5.1.2); other errors count as an empty answer |
| acl | full | `allow`/`block`/`filter`/`drop`, each with optional `type` and `net`. The first matching policy of the first matching rule decides; a rule with no matching policy passes the query to the next rule. Block and filter replies carry an EDE (Blocked 15 / Filtered 17) |
| any | full | RFC 8482 HINFO, TTL 8482 |
| chaos | full | Default version `CoreDNS-1.12 (stormcoredns-X)`. Authors are sorted and de-duplicated |
| loadbalance | full | `round_robin` (A/AAAA/MX in the answer and additional sections), or `weighted FILE { reload 30s }`. The weighted reload task leaks across reloads (#11) |
| tsig | partial | `secret NAME KEY` (works with the client's algorithm, as in CoreDNS), `secrets FILE`, `require all\|none\|TYPES`. Unsigned when required → REFUSED; a bad key or signature → NOTAUTH. **Only HMAC-SHA256/384/512 (hickory 0.24), and AXFR replies are not signed (#24)** |
| cache | full | Default capacity 9984 per store, max TTL 3600 (success) and 1800 (denial), min TTL 5. `prefetch` (60s window, 10%), `serve_stale` (1h, immediate\|verify), `servfail` (default 5s, as in CoreDNS), `disable`, `keepttl`. The cache key has no qclass |
| rewrite | full | `name` (exact/prefix/suffix/substring/regex, `answer auto\|name\|value`), `type`, `class`, `ttl`, `rcode`, `cname`, `edns0 local\|nsid\|subnet`; `stop` is the default. `answer auto` does not invert a regex. `ttl` clamps only answers whose owner matches |
| header | full | `query\|response set\|clear` for aa ra rd ad cd tc |
| dnssec | partial | Online signing as CoreDNS 1.12's `Sign`: RRSIGs on every RRset of a positive answer (answer, authority, additional); black-lie NSEC for NXDOMAIN/NODATA when the authority is one SOA (the queried type is left out of the bitmap, TTL from the SOA, rcode NOERROR; a query for NSEC gets it as the answer); referrals get their DS set signed or a delegation NSEC, never an RRSIG on the NS set; DNSKEY at the apex. Signature cache (default 10000) whose entries are re-signed within 2 days of expiry (8-day validity). Keys: ECDSA P-256/P-384 and Ed25519 in BIND or PEM/PKCS#8 format; **no RSA**. KSK/ZSK flags are ignored (every key signs) |
| autopath | full | `RESOLV-CONF`, `@kubernetes` (needs `pods verified`) or `@erratic` |
| minimal | full | Strips the authority and additional sections (keeping OPT) on a NOERROR reply that has answers |
| template | partial | `.Name .Question.Name .Zone .Class .Type .Remote .Message.Id`, `index .Match N`, `.Group.x`, `.Meta "l"`; **no Go template control structures, pipelines or functions (#21)**. A regex miss is SERVFAIL unless `fallthrough` covers the name; `rcode SERVFAIL` answers SERVFAIL; `ederror CODE [REASON]` adds an EDE; CNAME answers to A/AAAA are resolved through the server; a class/type ANY query matches every template. `upstream` is ignored, as in CoreDNS. Default TTL 3600 |
| transfer | full | `to IP[:port]\|*`. AXFR out is split into ~60 KB messages over TCP/DoT (DoH, DoQ and gRPC carry one message, so they send only the first; CoreDNS's DoH and gRPC also send one, the last). IXFR returns SOA-only when the serials are equal, otherwise a full transfer. NOTIFY to each `to` IP is a single UDP packet with no retry |
| hosts | full | Default `/etc/hosts`, TTL 3600, reload 5s (mtime); inline entries, `no_reverse`, `fallthrough`. As in CoreDNS: an unknown name falls through or gets SERVFAIL (there is no SOA for an NXDOMAIN); a name with only the other address family is NODATA and never falls through; PTR queries are answered outside the zones, and an unknown PTR goes to the next plugin |
| file | partial | `reload` default 60s, set per `file` stanza (`reload 0` disables it): the file is polled by mtime and reloaded when the serial changes, and NOTIFY is sent. Wildcards per RFC 4592 (only `*.<closest encloser>` synthesizes; an empty non-terminal is a closest encloser), CNAME chase (external targets resolved through the server itself, max 8 hops), DNAME (RFC 6672: the DNAME plus a synthesized CNAME with its TTL, YXDOMAIN when the new name is too long; carried as type 39 in AXFR), delegations with glue, empty non-terminals. Signed data (RRSIG, DS, NSEC or NSEC3 with the denial proofs of RFC 4035/5155) is served, but hickory's zone-file parser refuses RRSIG/NSEC/NSEC3/DNSKEY, so a signed zone *file* does not load (#20); signed zones arrive through `secondary`. A real `ANAME` record is refused, as in CoreDNS. `upstream` is accepted and ignored, as in CoreDNS |
| auto | full | `directory DIR [REGEXP TEMPLATE]` (default `db\.(.*)` → `{1}`), `reload` 60s. Every file is re-parsed on every tick. Lookup as in `file` (a signed zone file does not load, #20). `upstream` is accepted and ignored, as in CoreDNS |
| secondary | partial | `transfer from IP…`. AXFR in over TCP (no IXFR, no TSIG) and SOA polling. NOTIFY is accepted from primaries only. Queries get SERVFAIL until the first transfer. **SOA expire is ignored**; see #11. `upstream` is accepted and ignored, as in CoreDNS |
| etcd | full | SkyDNS layout (default path `/skydns`, endpoint `http://localhost:2379`): A/AAAA/CNAME/SRV/TXT/MX/PTR/NS/SOA, wildcards, `credentials`, `tls`, `fallthrough`. `upstream`/`stubzones` are ignored, as in CoreDNS. Default TTL 300 and priority 10, as in CoreDNS; etcd lease TTLs are not used |
| loop | full | A UDP probe to the first bind address, for the first zone, active for about 30 s after startup. Up to 3 attempts (2 s each), each with its own random name, so a slow or unreachable upstream is never taken for a loop; a loop is one probe name arriving more than twice, as in CoreDNS (#18, #9) |
| forward | full | `dns://` and `tls://` IP upstreams (at most 15 unless `sequential`). Policy `random` by default, also `round_robin`/`sequential`. `max_fails` 2, `expire` 10s, `health_check` 500ms (runs only after a failure), plus `except`, `force_tcp`, `prefer_udp`, `tls`, `tls_servername`, `max_concurrent` (over the limit → REFUSED), `next`, `failover`. There is a TCP/TLS connection pool (64 per upstream), and UDP opens a new socket per query. Timeouts: 5s each for dial and read, and 5s overall (or less, at the `cancel` deadline), which also bounds each upstream exchange. `next RCODE…` hands the query to the next plugin only when it is another `forward`, as in CoreDNS; `failover RCODE…` (not in CoreDNS 1.12) tries this forward's next upstream |
| grpc | full | tonic client, `tls`, `tls_servername`, `policy`, `except`; 5s timeout; no health checks |
| erratic | full | `drop`, `truncate` and `delay` (default every 2nd query counting from the first, 100 ms), `large` (30 A records). A 192.0.2.53, AAAA 2001:db8::53, AXFR a small zone (truncated transfers lack the closing SOA), any other type SERVFAIL. Ready only while the query count is 3 or 4, as in CoreDNS |
| whoami | full | A/AAAA plus SRV `_<proto>.<qname>` with the client port and target `.` |
| on | full | `startup`/`shutdown` commands. A command without `&` is waited for, and a failure fails the hook (a failed startup command stops the server starting); `&` runs it in the background |
| sign | partial | Offline NSEC chain, RRSIG and DNSKEY (CSK: every key signs everything), written to `db.<origin>.signed` in `directory` (default `/var/lib/coredns`). Signatures last 32 days. Re-signs when the source changes, or every ~6 days measured from process start. **No NSEC3, no CDS/CDNSKEY**; `key directory` only picks up `K*.key`. **`file` cannot load the signed file it writes**, and a source that already holds DNSSEC records fails (#20) |
| view | partial | Language: `name() type() class() proto() size() port() id() opcode() do() bufsize() client_ip() server_ip() server_port() incidr()`, `in matches contains startsWith endsWith`, comparisons, arithmetic, `and or not`/`&& \|\| !`. Several `expr` lines are ANDed. **`metadata()` is always empty** (#12) |
| kubernetes | full | `endpoint`, `tls`, `kubeconfig`, `namespaces`, `namespace_labels`, `labels`, `pods disabled\|insecure\|verified` (default disabled), `endpoint_pod_names`, `ttl` (default 5), `noendpoints`, `startup_timeout` (default 5s: startup waits for the API to sync, as in CoreDNS), `fallthrough`, `ignore empty_service`. EndpointSlices, falling back to core Endpoints. `multicluster` is rejected. EndpointSlice discovery retries transient errors. See [integration.md](integration.md) |
| k8s_external | full | LoadBalancer ingress and externalIPs, hostnames as CNAME (resolved through the server for A/AAAA), SRV, `headless` (each ready endpoint is `<endpoint>.<service>.<namespace>.<zone>` and the SRV target), PTR, `apex` (default `dns`), `ttl` (default 5), `fallthrough` |
| clouddns | full | `clouddns ZONE:PROJECT_ID:HOSTED_ZONE_NAME...`, `credentials FILE` or `GOOGLE_APPLICATION_CREDENTIALS` or the GCE metadata server, `fallthrough`. Refresh every 60s. Fetched in the background: `/ready` is 503 until every zone has loaded once (CoreDNS fetches at startup and refuses to start when a zone fails, and has no readiness for it) |
| azure | full | `tenant`, `client`, `secret`, `subscription` (or `AZURE_*`), `environment` (public, US Gov or China cloud), `access public\|private`, `fallthrough`. Refresh every 60s. Record properties are read case-insensitively (the private DNS API is camelCase). Fetched in the background: `/ready` is 503 until every zone has loaded once (CoreDNS fetches at startup and refuses to start when a zone fails, and has no readiness for it) |
| route53 | partial | SigV4 (us-east-1, Route 53's signing region). Credentials from `aws_access_key`, `credentials PROFILE [FILE]`, `AWS_*` env or the shared credentials file (`AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`); **no web identity (IRSA), ECS or IMDS (#23)**. Alias record sets are skipped, as in CoreDNS. `refresh` 60s, with pagination. Fetched in the background: `/ready` is 503 until every zone has loaded once (CoreDNS fetches at startup and refuses to start when a zone fails, and has no readiness for it) |

The parser handles `import` (files, globs, snippets), not a plugin. It only
works inside a server block.

## Metrics

Plugin metric names are `coredns_*`, served from one registry, plus the Go
client's `process_*` metrics (`process_cpu_seconds_total`, `process_open_fds`,
`process_max_fds`, `process_virtual_memory_bytes`,
`process_virtual_memory_max_bytes`, `process_resident_memory_bytes`,
`process_start_time_seconds`, read from `/proc/self`). There are no `go_*`
metrics.

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
- **acl**: `acl_{allowed,blocked,filtered,dropped}_requests_total` (allowed
  is labelled `server`, `view`; the others `server`, `zone`, `view`).
- **template**: `template_matches_total`, `template_template_failures_total`,
  `template_rr_failures_total`.
- **dnssec**: `dnssec_cache_entries`, `dnssec_cache_hits_total`,
  `dnssec_cache_misses_total`.
- **hosts**: `hosts_entries`, `hosts_reload_timestamp_seconds`.
- **others**: `dns64_requests_translated_total`, `autopath_success_total`,
  `local_localhost_requests_total`.
