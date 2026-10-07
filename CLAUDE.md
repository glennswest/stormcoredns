# CLAUDE.md — stormcoredns

A Rust reimplementation of [CoreDNS](https://coredns.io): same Corefile
syntax, same plugin-chain model, same plugin names and directives, same
external APIs (DNS over UDP/TCP/TLS/HTTPS/QUIC/gRPC, Prometheus metrics,
`/health`, `/ready`, dnstap, reload). Design notes are in
[docs/architecture.md](docs/architecture.md); the plugin authoring contract
is [docs/plugin-api.md](docs/plugin-api.md); per-plugin status is in
[docs/plugins.md](docs/plugins.md).

## Version

`0.1.1` (tag v0.1.1) — defined in `Cargo.toml` only (`src/main.rs` reads
`env!("CARGO_PKG_VERSION")`).

## Build, test, ship

Never build on the stormcentral VM and never `ssh root@` anywhere. Push, then:

```bash
sc-build                        # cargo build && cargo test on dev.g8.lo, scratch dir, deleted after
sc-build 'cargo test cache'     # any command
```

`build.rs` needs `protoc` (tonic-build for `proto/dns.proto`).

It ships as the **`coredns` golden**, built by stormcos's builder in stage
mode (special golden; stormcentral `src/goldens.rs` maps it to
`STORMCOREDNS_SRC`). When an issue's work is pushed and sc-build passes:

```bash
stormcentral component stage coredns --url http://stormcentral.g8.lo
```

No image registry is involved (the mkube registry was retired 2026-08-27);
`Containerfile` and `deploy/kubernetes/coredns.yaml` are for non-stormcos
clusters only. stormcos runs it from `deploy/manifests/80-coredns.yaml`
(`command: ["/coredns"]`, forward to 192.168.8.252). Details:
[docs/integration.md](docs/integration.md).

## Layout

```
src/main.rs            flags (hand-parsed, Go flag style): -conf -dns.port/-p -pidfile -quiet/-q -version/-v -plugins; PORT env; signals; reload loop
src/corefile/          Caddyfile-v1 lexer + parser (import, snippets, {$ENV}/{%ENV%}) + Dispenser
src/plugin/            Handler trait, Next, Request, Reply, PluginError, Controller, registry (plugin.cfg order), replacer
src/server/            key parsing, listener grouping, UDP/TCP/DoT/DoH/DoQ/gRPC, zone+view dispatch, self_lookup
src/plugins/           one module per directive (prometheus = metrics.rs; file/, dnssec/, kubernetes/ are dirs)
src/dnsutil/           name helpers, reverse zones, upstream parsing, EDNS0, durations
src/metrics.rs         global Prometheus registry + core metrics
docs/                  architecture, plugin API, per-plugin status + metrics, stormcos integration, presentation.md (Marp)
examples/              Corefiles + a zone file
test/                  stormcoredns-test: the test container (/test short|medium|long, test/README.md); workspace member, not in the golden build
```

## Work plan

Priority order came from the owner (2026-08-29): Kubernetes cluster DNS
first, then the plugins that let one server also serve site zones (the
MicroDNS consolidation path: `view`, `transfer`, `secondary`).

### Phase 1 — core ✅
- [x] Corefile lexer/parser/Dispenser (import, snippets, env vars, blocks)
- [x] Plugin trait, chain, request/reply, registry in plugin.cfg order
- [x] Server: zone dispatch, UDP+TCP, TLS, DoH, DoQ, gRPC listeners, reload/SIGHUP/SIGUSR1
- [x] main.rs CLI matching `coredns` flags
- [x] Smoke-tested on dev: UDP/TCP answers, cache hit, forward, health/ready/metrics

### Phase 2 — essential for a cluster
- [x] errors health ready prometheus forward cache loop reload loadbalance
- [x] log bind debug root whoami
- [x] kubernetes (Services, headless, SRV, PTR, pods, ExternalName, fallthrough; EndpointSlices with core Endpoints fallback)

### Phase 3 — high value ✅
- [x] autopath hosts rewrite template view transfer acl k8s_external cancel bufsize

### Phase 4 — authoritative ✅
- [x] file auto secondary dnssec sign (ECDSA/Ed25519 keys; RSA needs OpenSSL)

### Phase 5 — operational / transport / backends ✅
- [x] pprof(partial) trace(partial: no exporter) nsid chaos header minimal timeouts metadata multisocket
- [x] tls, grpc (client), dnstap, tsig, dns64, any, local, erratic, geoip, on
- [x] etcd route53 azure clouddns
- [ ] kubernetai (external plugin, multi-cluster) — not started

### Phase 6 — release
- [x] Docs (README, architecture, plugin API, plugin status), example Corefiles, Containerfile (scratch)
- [x] Live smoke test on dev: file zone (wildcards, CNAME, delegation, glue), AXFR over TCP with view, hosts, rewrite→template, health/ready/metrics
- [x] v0.1.0 tagged 2026-08-29 (release binary 14.8 MB, 53 directives)
- [x] v0.1.1 (2026-08-30): plugin.cfg order fix for #1 (kubernetes before forward); release assets attached
- [x] Container image built with podman on dev: `localhost/stormcoredns:0.1.0` (scratch, musl static, 15.1 MB)
- [x] GitHub release v0.1.0 carries the image as a docker-archive tar (`stormcoredns-0.1.0-image.tar.gz`), the static binary and SHA256SUMS; assets are built into `/build/assets/stormcoredns` on dev
- [x] ~~Pushed to the mkube registry~~ — superseded: mkube retired 2026-08-27; delivery is the `coredns` golden (#2)
- [x] `deploy/kubernetes/coredns.yaml` + `docs/integration.md` for the stormcos integration (asked for by the owner 2026-08-30)
- [x] Runs against rustkube as the cluster DNS (stormcos 11.03, 2026-09-21: `kubernetes.default.svc.cluster.local` → 10.96.0.1)
- [ ] Test containers per the stormcos test standard (#5) — built; first in-cluster run pending (see below)
- [ ] trace exporter (OTLP/Zipkin), NSEC3 in `file`/`sign`, CDS/CDNSKEY in `sign`, `kubernetes multicluster`

### Done — #3 docs from the code (2026-09-26)
- [x] README, docs/, CLAUDE.md and module docs rewritten from the code as it is now; delivery is the `coredns` golden built by stormcos stage mode (also closes #2: no mkube registry)
- [x] Every doc claim the code does not back filed as an issue (#6–#16)
- [x] sc-build green (de6be9a, 54 tests), #2 and #3 closed

### Done — #4 presentation (2026-09-26)
- [x] `docs/presentation.md`: Marp deck (14 slides) drawn from the #3 docs, every claim checkable against the code; renders with `npx @marp-team/marp-cli@4`
- [x] stormcentral's graph has `stormcoredns depends_on stormd`, but the `coredns` golden is a bare binary (no stormd) — filed stormcentral#35; the slide shows the real runtime dependencies

### In progress — #5 test containers (2026-09-27)
Design (stormcentral `docs/test-standard.md`, runner `src/testruns.rs`):
the runner applies its own Job (`/test <suite>`, plain pod, SA `storm-test`
with `*` in the run's namespace only, no cluster read). So the test finds the
cluster DNS from its own `/etc/resolv.conf` (nameserver + `<ns>.svc.<domain>`
search, written by rustkube-node's kubelet) and checks it against Services,
Endpoints and EndpointSlices it creates in its own namespace.
- [x] `test/` crate `stormcoredns-test` (workspace member; tokio, hickory-proto, reqwest, serde_json, anyhow — already in Cargo.lock; lock entry hand-added, verified by `--locked`), `test/build.sh`, `test/Containerfile` (scratch), `test/README.md` with metadata
- [x] short: SOA at the apex, Service A over UDP+TCP, SRV, NXDOMAIN+SOA, delete → NXDOMAIN
- [x] medium: headless A/SRV/hostnames, PTR, ExternalName, pods, dns-version, endpoint change, UDP truncation vs TCP/EDNS, FORMERR, forward path, case, concurrency
- [x] long: waves of Services ramped until the cluster pushes back; programming latency, query p50/p99, drain residue, probe slowdown vs wave 1
- [x] sc-build `cargo build --locked --workspace && cargo test --locked --workspace && STAGE_ONLY=1 test/build.sh` green (491a7af; 3.4 MB static binary)
- [ ] **Blocked:** first real run. stormcentral#56 is fixed (20a570b) and C2NR0Q2's apiserver now answers, but run 54b2f2032b (2026-09-27, 4695f5d) stopped at the image step: C2NR0Q2's sbregistry refuses connections on :5100 (same for every component's run) — filed stormcentral#71 (runner side; node side is stormcos#135). Also filed stormcentral#83 (Decide: more test machines). 2026-09-28 validation: `:5100` answers again (C2NR0Q2 on 11.51), but pushes fail with a registry 500 or broken pipe (runs fe3fc66b32, fd3f8a1fe0). That is stormblock-registry#56, fixed in v0.24.1 but not yet on the node; the root cause of the registry dropping, stormpump#54, is unreleased too. When C2NR0Q2 has a release with v0.24.1: `stormcentral test run stormcoredns short|medium --tag C2NR0Q2 --url http://stormcentral.g8.lo`, fix what it finds, then close #5.

### Done — docs refresh, third pass (2026-09-27)
- [x] No code changes since 06ff80c; integration.md now notes the ironprom scrape of `10.96.0.10:9153` and the missing Service port (filed stormcos#152)

### Done — #18 loop false positive (P0, stormcos#261, 2026-10-06)
- [x] Each startup probe attempt gets its own qname; a loop is one qname arriving more than twice (CoreDNS's threshold), so retries after a slow/unreachable upstream never count. Also closes #9.
- [x] 3 unit tests; sc-build green at 219c6ad, with live checks on dev: `forward . 192.0.2.1` stays up (3 unanswered probes, warnings only), `forward` to itself still exits 1 on the loop
- [x] `coredns` golden staged

### Done — #16 dead hooks and unused fields (2026-10-06)
- [x] Wired: `on_restart` (before each reload; an error aborts it) and `on_restart_failed` are repeatable `RestartHook`s kept by the instance; `Instance::stop` uses `Server.graceful_timeout`; `forward` stops at the `cancel` deadline, and its 5 s budget bounds each exchange
- [x] Removed: `Handler::health()`, `BuildOptions.quiet`, `ServerConfig.{debug,stacktrace,metadata}`, `Server.debug`, `ParsedKey.ipv4_only`, `file::zone::{quick_serial,unused_bail,NameData::is_empty}` (the build is warning-free)
- [x] Ignored options documented per plugin in docs/plugins.md (`upstream`/`stubzones` ignored as in CoreDNS); `pprof block` and trace exporter options warn
- [x] sc-build green at 2ab4c86: no warnings, 59+6 tests, live SIGHUP reload + SIGTERM exit on dev. Live scripts: the binary is `${CARGO_TARGET_DIR:-target}/debug/stormcoredns` (CARGO_TARGET_DIR is set on dev — that is what #19 tripped on)

### Done — #13 file: wildcards, reload, DNAME, NSEC3 (2026-10-06)
- [x] Wildcards per RFC 4592: only `*.<closest encloser>` synthesizes (names + empty non-terminals precomputed in `Zone.nodes`); NSEC proofs use the closest encloser
- [x] `reload` per `file` stanza
- [x] DNAME (RFC 6672): the zone text's DNAME type token is parsed as ANAME (`dname_as_aname`) and stored as type 39; DNAME + synthesized CNAME, YXDOMAIN when too long; a real ANAME is refused
- [x] NSEC3 denial proofs (RFC 5155 7.2): NXDOMAIN, NODATA/opt-out, wildcard answer/NODATA, referral
- [x] sc-build green at c35d48d (68+6 tests, no warnings) + live check on dev (closest-encloser NXDOMAIN, DNAME chain, YXDOMAIN, per-stanza reload); golden `golden-coredns-f17e28c24280` (stormcos#348)
- [x] Found: hickory 0.24's zone parser refuses RRSIG/NSEC/NSEC3/DNSKEY, so signed zone files (and `sign`'s output) don't load in `file` — filed #20

### In progress — #15 CoreDNS 1.12 divergences (2026-10-06)
Checked against CoreDNS v1.12.4 source (cloned into `tmp/coredns-1.12`, not committed).
Fix here, item by item (commit each group):
- [ ] defaults: `bufsize` 1232; `cache` SERVFAIL 5 s; `etcd` TTL 300 / priority 10
- [ ] syntax: `clouddns ZONE:PROJECT:HOSTED_ZONE`; `forward next` hands the reply to a following `forward` (upstream has no `failover`; ours stays as an extension)
- [ ] behaviour: acl falls through to the next rule; hosts NXDOMAIN/fallthrough; template regex miss; dns64 leaves NXDOMAIN alone; whoami SRV; reload hash sha512; `on` waits without `&`; kubernetes in-cluster first; azure private casing; erratic AXFR; local zones; others as found
Split into their own issues if large: Go template functions, dnstap FORWARDER_*, route53 IMDS/IRSA/profile, process_* metrics, rustls client_auth, AXFR over DoH/DoQ/gRPC
- [x] All fixes pushed (through aa3c367); split out #21 template, #22 dnstap FORWARDER, #23 route53 IRSA/IMDS, #24 tsig MD5/SHA1/AXFR
- [x] docs (plugins.md, README, integration.md, presentation), CHANGELOG
- [ ] **Blocked:** sc-build verification. b51de9e (through erratic) was green (73+6 tests, no warnings); the full job at aa3c367 got no build slot four times in a row (exit 75, P3 starved, stormcentral#505); item proposed after it. Next: run `tmp/job15.sh`'s steps (full build + test + live check of whoami/local/hosts/acl EDE/template/erratic AXFR/process metrics/reload), fix what fails, stage `coredns`, close #15

### In progress — #14 kubernetes/cloud readiness and discovery (2026-10-07)
Checked against CoreDNS v1.12.4: it does not SERVFAIL before sync; its startup hook waits for the API to sync, up to `startup_timeout` (default 5s), then serves what it has.
- [x] kubernetes: wait for sync in the startup hook, `startup_timeout DURATION` (default 5s), as CoreDNS
- [x] kubernetes: EndpointSlice discovery with a timeout; transient errors retry in the background instead of locking in core Endpoints (CoreDNS 1.12 is slices-only; our Endpoints fallback stays as an extension for rustkube)
- [x] kubernetes: `set_slice` keeps an IP→service index entry while another slice of the service still has the IP
- [x] kubernetes: `endpoint https://` without `tls` verifies against the system roots (as CoreDNS) instead of skipping verification; `tls` without `endpoint` warns
- [x] route53/azure/clouddns: ready only once every zone has been fetched successfully
- [x] tests (slice index, discovery against a fake API server, cloud readiness), docs, CHANGELOG — pushed through 01000ea
- [ ] **Blocked:** sc-build. The combined #15+#14 job (`tmp/job15.sh`: full build, tests, #15 live check) at 01000ea got no slot (exit 75, stormcentral#505). Then: fix what fails, stage `coredns`, close #14 and #15

### In progress — #10 dnssec black lies and signature cache (2026-10-07)
Checked against CoreDNS v1.12.4 `plugin/dnssec` (`Sign`, `black_lies.go`, `cache.go`).
- [x] black lies as upstream: NXDOMAIN and NODATA bitmaps drop the queried type (unless NSEC); delegation bitmap for referrals and DS; LOC/CERT/HIP/SPF in the bitmaps; NSEC TTL from the SOA; a qtype NSEC query gets the NSEC as the answer
- [x] negatives signed only when the authority is exactly one SOA (as upstream)
- [x] referrals: sign DS only, or a delegation NSEC; the NS set and glue are not signed
- [x] positive answers: additional section signed too
- [x] signature cache: an entry whose RRSIG expires within 2 days is re-signed
- [x] tests, docs, CHANGELOG (through 811f088)
- [ ] **Verification (also for #14 and #15):** the combined job (`tmp/job15.sh`) at 28a1490 (#25 closed) ran: workspace builds with no warnings, 81/82 tests pass, every #15 live check as intended (whoami SRV, local, hosts SERVFAIL/NODATA, acl EDE 15/17, template SERVFAIL, erratic SERVFAIL + 6-record AXFR, process_* + reload sha512, reload on edit). The one failure (black-lie NSEC next name lost `\000`, also before #10) is fixed in 811f088; the rerun got no slot twice (exit 75, stormcentral#505). Next: rerun, then stage `coredns`, close #10, #14, #15

### In progress — #12 view metadata() (2026-10-07)
CoreDNS 1.12 (`core/dnsserver/server.go`): for each candidate config, the first metadata plugin's `Collect` runs before that config's view filters, so `metadata()` sees the providers' labels.
- [x] `metadata` keeps a collector on its `ServerConfig`; `Server::lookup` collects before each filter; the plugin's own `serve_dns` only passes on
- [x] unit test `server::tests::view_filters_see_collected_metadata` (real view expression + collector + `Server::lookup`; a live check needs a geoip DB, which dev lacks), docs, CHANGELOG — pushed through 8cc4fc8
- [ ] **Blocked:** sc-build at 8cc4fc8 (the combined `tmp/job15.sh`, which also verifies #10, #14, #15): dev.g8.lo refused ssh on :22 twice (exit 255, stormcentral#97). Then stage `coredns`, close #10, #12, #14, #15

### In progress — #11 secondary timers (2026-10-07)
Checked against CoreDNS v1.12.4 `plugin/file/secondary.go` and `plugin/secondary/setup.go`.
- [x] initial transfer retried with backoff 250ms→10s until it succeeds
- [x] after a failed refresh check/transfer: retry every SOA `retry`; once `expire` has passed since the last good check the zone is expired → SERVFAIL (and no AXFR out) until a transfer succeeds
- [x] serial compare per RFC 1982 (`less`, as upstream); the SOA check goes over TCP like upstream
- [x] refresh tasks stop on shutdown/reload (cancellation token); same for `loadbalance weighted`'s reload task
- [x] NOTIFY only from a primary's IP (documented)
- [x] tests (`serial_arithmetic`; `refresh_retry_expire` against a fake TCP primary: backoff, NOTIFY refresh, no downgrade, expiry → SERVFAIL/no AXFR out, recovery, shutdown), docs, CHANGELOG — pushed through 62509ef
- [ ] **Blocked:** sc-build (combined `tmp/job15.sh`, also for #10/#12/#14/#15): dev.g8.lo unreachable (no route to host / refused, stormcentral#97). Then stage `coredns`, close #10, #11, #12, #14, #15

### In progress — #8 `:port` IPv4-only after a reload (2026-10-07)
- [x] `resolve_bind`: dual stack when IPv6 is usable (probe `[::]:0` once, cached), not by binding the real port (held by the old instance during a reload, or privileged)
- [x] test `port_held_by_another_listener_stays_dual_stack`, docs, CHANGELOG — pushed through 72c1180
- [ ] **Blocked:** sc-build of `tmp/job_all.sh` (= `job15.sh` + `live8.sh`: v4/v6 queries before and after SIGHUP and a Corefile-edit reload) — dev.g8.lo: no route to host (stormcentral#97). One passing run verifies #8, #10, #11, #12, #14, #15; then stage `coredns` and close them

### Done — #17 presentation: stormcos#79 done (2026-10-07)
- [x] Checked in stormcos (build-goldens.sh, 80-coredns.yaml, #79 closed 2026-09-30); slide updated in c1b91b4; docs-only, closed

### Next — bugs found by the #3 audit
Cluster-DNS path first (stormcos runs `lameduck 5s` + `reload` + `loop`):
- [ ] #6 `/health` stuck 503 after a reload with lameduck
- [ ] #7 a failed reload stops automatic reloads
- [ ] #20 signed zone files do not load (hickory parser)
