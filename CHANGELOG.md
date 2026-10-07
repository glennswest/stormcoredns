# Changelog

## [Unreleased]

### 2026-10-07 (#10)
Checked against CoreDNS v1.12.4 `plugin/dnssec`.
- **fix:** Black-lie NSEC for NXDOMAIN (as well as NODATA) leaves the queried type out of its bitmap. Before, an NXDOMAIN turned into NOERROR claimed the type existed, and validators found that bogus. A query for NSEC keeps it in the bitmap and gets the NSEC as the answer.
- **fix:** The black-lie NSEC TTL comes from the SOA in the response, not a fixed 3600. Negatives are signed only when their authority is exactly one SOA, as in CoreDNS.
- **fix:** Referrals sign only the DS set. Without a DS, they add an NSEC with CoreDNS's delegation bitmap (next name `<label>\000.<rest>`). The NS set and glue are no longer signed.
- **fix:** A cached signature is re-made once it is within 2 days of its 8-day expiry. Before, a busy RRset kept its RRSIG past expiration until the LRU evicted it.
- **fix:** Positive answers also sign the additional section. The bitmaps include LOC, CERT, HIP and SPF, as upstream's do.
- **docs:** plugins.md, README and the presentation.

### 2026-10-07 (#14)
Checked against CoreDNS v1.12.4 first. CoreDNS does not answer SERVFAIL before the API syncs: its startup hook waits for the sync, up to `startup_timeout`.
- **fix:** `kubernetes` startup waits for every watch to sync, up to `startup_timeout DURATION` (new option, default 5s), as CoreDNS does, so a new server no longer answers NXDOMAIN from empty caches in its first moments. On a reload the old instance keeps serving meanwhile.
- **fix:** `kubernetes` EndpointSlice discovery has a 5s timeout. A transient error (timeout, connection error, 5xx) is retried in the background with backoff, instead of settling on core Endpoints for the life of the instance. A 404 for the group still selects core Endpoints.
- **fix:** `kubernetes`: removing or updating one EndpointSlice no longer drops a pod IP from the reverse (PTR) index while another slice of the same service still has it.
- **fix:** `kubernetes endpoint https://…` without `tls` verifies the API server against the system roots, as CoreDNS does, instead of accepting any certificate. `tls` without `endpoint` (or with `kubeconfig`) logs a warning that it is unused.
- **fix:** `route53`/`azure`/`clouddns` report ready only once every zone has loaded at least once. Before, the first refresh marked them ready even if every fetch failed.
- **docs:** integration.md, plugins.md, README and the presentation. Unlike CoreDNS, the cloud backends still start without their zones and report it on `/ready`.

### 2026-10-06 (#15)
CoreDNS 1.12 differences from the docs audit, each checked against CoreDNS v1.12.4's source first.
- **BREAKING:** `clouddns` takes `ZONE:PROJECT_ID:HOSTED_ZONE_NAME` as CoreDNS does. The old `PROJECT:ZONE[:ORIGIN]` form is rejected.
- **fix:** Defaults now match CoreDNS: `bufsize` 1232, `cache` caches SERVFAIL for 5 s, `etcd` TTL 300 and SRV/MX priority 10, `timeouts` read 3 s and write 5 s.
- **fix:** `forward next RCODE…` hands the query to the next plugin only when it is another `forward`, and does not retry this forward's upstreams. `failover` (not in CoreDNS 1.12) keeps doing that.
- **fix:** `acl`: a rule with no matching policy passes the query to the next rule. Block and filter replies carry an EDE (15/17). The allowed counter is labelled `server`, `view`.
- **fix:** `hosts`: an unknown name gets SERVFAIL (or falls through), a name with only the other address family is NODATA and never falls through, PTR is answered outside the zones, and an unknown PTR goes to the next plugin.
- **fix:** `template`: a regex miss is SERVFAIL unless `fallthrough` covers the name. `rcode SERVFAIL` answers SERVFAIL. `ederror CODE [REASON]` adds an EDE. CNAME answers to A/AAAA are resolved through the server. A class/type ANY query matches every template, and an RR that does not parse is SERVFAIL.
- **fix:** `dns64` returns NXDOMAIN unchanged (RFC 6147 5.1.2) and treats other errors as an empty answer.
- **fix:** `whoami` SRV is `_<proto>.<qname>` with target `.`.
- **fix:** `reload` hashes the parsed Corefile (imports expanded) with SHA-512, skips edits that do not parse, and reports `reload_version_info{hash="sha512"}`.
- **fix:** `on` waits for commands without `&`, and a failed command fails its startup/shutdown hook.
- **fix:** `kubernetes` without `kubeconfig`/`endpoint` uses only the in-cluster config, as CoreDNS does; `$KUBECONFIG` and `~/.kube/config` are no longer read.
- **fix:** `azure` reads private DNS zones' camelCase record properties (`ttl`, `aRecords`, …).
- **fix:** `erratic` answers every type itself (others SERVFAIL), sends a real small AXFR, counts queries from 0 and is ready only at query counts 3–4.
- **fix:** `local` is a port of CoreDNS's plugin: `0.`/`127.`/`255.in-addr.arpa.` zones, `localhost.<domain>`, and `coredns_local_localhost_requests_total`. It no longer answers `ip6-localhost`, `localhost.localdomain` (now via the `localhost.` prefix rule) or `::1`'s reverse name.
- **fix:** `route53` skips alias record sets, as CoreDNS does, and falls back to the shared credentials file (`AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`).
- **fix:** `dnstap` accepts host names in `tcp://`/`tls://` endpoints, and counts dropped messages and logs the count every second.
- **fix:** `tsig`: a `secret NAME KEY` works with the client's algorithm.
- **fix:** `tls client_auth request|require` take any client certificate unverified. The verify modes fall back to the system roots, so the CA is optional, as in Go.
- **fix:** `timeouts` apply to DoH: read covers the TLS handshake and request body, write covers producing the answer, idle covers the time between requests.
- **fix:** `debug` turns panic recovery off: a panic exits the process (status 2).
- **fix:** `k8s_external headless` serves `<endpoint>.<service>.<namespace>.<zone>` and uses it as the SRV target. LoadBalancer hostname CNAMEs are resolved for A/AAAA.
- **feat:** `process_*` metrics from `/proc/self`.
- **docs:** plugins.md, README, integration.md and the presentation. What is left is filed: #21 (template Go functions), #22 (dnstap FORWARDER), #23 (route53 IRSA/ECS/IMDS), #24 (tsig MD5/SHA1/SHA224 and AXFR signing). Verified as not a difference: route53's SigV4 region (Route 53 signs in us-east-1). AXFR over DoH/DoQ/gRPC carries a single message in CoreDNS too.

### 2026-10-06 (#13)
- **fix:** `file` wildcards follow RFC 4592: only `*.<closest encloser>` synthesizes an answer. Before, any `*.` ancestor did, so `x.b.c.example.org` got the apex wildcard even though `a.b.c.example.org` exists, where the answer should be NXDOMAIN. Existing names and empty non-terminals are computed once at load. NSEC proofs for NXDOMAIN now name the closest encloser's wildcard instead of the parent's.
- **fix:** `reload` in a `file` stanza applies to that stanza's zones only. Before, the last `reload` in the server block applied to every stanza.
- **feat:** DNAME (RFC 6672) in `file`, `auto` and `secondary` zones. The answer is the DNAME plus a CNAME synthesized with the DNAME's TTL, then the chase continues. YXDOMAIN is returned when the new name would be longer than 255 octets. A DNAME occludes delegations below it. hickory 0.24 cannot parse DNAME, so the zone text's DNAME type field is parsed as ANAME and stored as type 39 (a real ANAME is refused, as in CoreDNS). AXFR carries DNAME as type 39.
- **feat:** NSEC3 denial proofs (RFC 5155 7.2) for signed zones: NXDOMAIN, NODATA (including opt-out), wildcard answers, wildcard NODATA and referrals without DS. The parameters come from the apex NSEC3PARAM.
- **docs:** plugins.md (file, auto, sign), README and the presentation. Filed #20: hickory's zone-file parser refuses RRSIG/NSEC/NSEC3/DNSKEY, so signed zone *files* (including `sign`'s output) do not load in `file`/`auto`.

### 2026-10-06 (#16)
- **fix:** `on_restart` hooks now run before every reload (an error aborts that reload and keeps the running instance), and `on_restart_failed` hooks run on every failed reload, not just the first. Both are now `RestartHook`s (`Arc<dyn Fn>`).
- **fix:** `Instance::stop` waits up to the servers' `graceful_timeout` overall, instead of a hardcoded 5 s per listener task.
- **fix:** `forward` honours the `cancel` deadline (`req.deadline`). It stops trying upstreams once the deadline passes, and its 5 s overall budget now bounds each upstream exchange too.
- **refactor:** Removed dead code: `Handler::health()`, `BuildOptions.quiet`, `ServerConfig.{debug,stacktrace,metadata}`, `Server.debug`, `ParsedKey.ipv4_only`, and `file::zone::{quick_serial,unused_bail,NameData::is_empty}`. The build has no warnings now.
- **chore:** `pprof { block }` and the `trace` exporter options log a warning that they are ignored.
- **docs:** plugin-api.md, architecture.md, plugins.md, README and the presentation now describe the restart hooks, the grace time, and which options are ignored (`upstream`/`stubzones` are ignored in CoreDNS too).

### 2026-10-06 (#18)
- **fix:** `loop` no longer exits when the upstream is slow or unreachable (stormcos#261). The startup probe was retried with the same name after a 2 s timeout, and the second arrival counted as a loop. Each attempt now has its own random name, and a loop is one name arriving more than twice (CoreDNS's threshold, also #9). A probe with no answer is logged as a warning, never fatal. Verified with sc-build at 219c6ad: unit tests pass, a server forwarding to an unreachable upstream stays up, and a server forwarding to itself still exits on the loop.

### 2026-09-28 (issue validation)
- **docs:** Work plan: #5 is still blocked. C2NR0Q2's registry connects now, but image pushes fail (stormblock-registry#56, fixed in v0.24.1 but not yet deployed). #2, #3 and #4 are still closed, and their evidence still holds.

### 2026-09-27 (docs refresh, third pass)
- **docs:** Re-checked against the code and history since 2026-09-18. There have been no code changes since 06ff80c. The golden (`STORMCOREDNS_SRC` in stormcentral `src/goldens.rs`, stormcos#107), `80-coredns.yaml` and `build-goldens.sh` are unchanged. New since the last pass: stormcos 198d8a2 (#64) makes the node's ironprom scrape `10.96.0.10:9153`, but the `kube-dns` Service declares no 9153 port. `docs/integration.md` now says who scrapes `/metrics` and that `:9153` binds every address; filed stormcos#152 for the missing Service port. There are no new stormcoredns gaps beyond #6–#16.

### 2026-09-27 (docs refresh, second pass)
- **docs:** Re-checked README, docs/, test/README.md and CLAUDE.md against the code and history since 2026-09-18. No code has changed since the morning refresh (06ff80c); only docs have. External facts re-verified: stormcentral `src/goldens.rs` still stages `coredns` from `STORMCOREDNS_SRC` (a stage-only golden, so it is absent from `stormcentral component list`); stormcos `build-goldens.sh` still builds the musl binary, stages `/stormcoredns` + `/coredns` as a 32M golden, with no upstream fallback; the latest golden is still `golden-coredns-0f272e81c6e0` (stormcos#107, open); `80-coredns.yaml`'s stale fallback comment is still stormcos#79. Nothing the docs promise that the code does not do beyond #6–#16, so no new issues.

### 2026-09-27 (#5 run attempt)
- **docs:** Work plan: #5's first in-cluster run (54b2f2032b) now gets past the apiserver wait and stormcentral#56, and stops at C2NR0Q2's sbregistry refusing :5100; filed stormcentral#71.

### 2026-09-27 (docs refresh)
- **docs:** Docs re-checked against the code and history since 2026-09-18. The server code is unchanged since the #3 rewrite. The stormcos coredns path (`80-coredns.yaml`, `build-goldens.sh`, golden `golden-coredns-0f272e81c6e0`) and stormcentral's test runner match what is documented. Fixed: `test/README.md` said a node without cluster DNS fails "at apex-soa" (only the short suite has it) and that `forward-answers` sends one query (it retransmits once); the README now counts the test crate's unit tests; CLAUDE.md's layout lists `test/`. Nothing new the docs promise that the code does not do; the open gaps remain #6–#16.

### 2026-09-27 (#5)
- **test:** `test/`, the `stormcoredns-test` container per the stormcos test standard: `/test short|medium|long` against the cluster DNS from a pod, with JSON-lines results and exit 0/1/2. It finds the server and cluster domain in the pod's resolv.conf and checks against Services, Endpoints and EndpointSlices it creates in the run's namespace. short: SOA, Service A over UDP/TCP, SRV, NXDOMAIN, delete. medium: headless, PTR, ExternalName, pods, truncation vs TCP/EDNS, FORMERR, forward, load. long: overnight waves of Services with latency, residue and trend. `test/build.sh` builds the static binary; `test/Containerfile` packages it FROM scratch.
- **build:** the repo is a Cargo workspace (`.`, `test`); the root package stays the default member, so the golden build is unchanged.

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
