# stormcoredns

CoreDNS, reimplemented in Rust. It reads a Corefile, builds CoreDNS's plugin
chain in CoreDNS's `plugin.cfg` order, and serves DNS over UDP, TCP, TLS,
HTTPS, QUIC and gRPC. The flags, directive names, metric names and HTTP
endpoints are CoreDNS's, so a kube-dns ConfigMap or a `forward`/`cache`
resolver Corefile runs unchanged. The same holds for most authoritative
`file`/`transfer` setups.

In stormcos it is the cluster DNS: the `coredns` golden holds this binary.
It answers `cluster.local` from the Kubernetes API and forwards everything
else to the site's MicroDNS. See [Shipping](#shipping).

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

Version **0.1.1**, tracking CoreDNS **1.12** (`-version` prints
`stormcoredns-0.1.1 (CoreDNS-1.12 compatible)`).

## What it does today

The binary recognises all **53** directives in CoreDNS 1.12's `plugin.cfg`,
and every one has an implementation (`-plugins` lists them). Most are complete.
Some are partial or differ from CoreDNS in ways you can observe;
[docs/plugins.md](docs/plugins.md) has the per-plugin status, and
[Known gaps](#known-gaps) summarises them below.

| area | plugins |
|---|---|
| cluster DNS | `kubernetes` `k8s_external` `autopath` `forward` `cache` `loop` `loadbalance` `reload` `health` `ready` `prometheus` `errors` |
| queries & answers | `rewrite` `template` `hosts` `acl` `view` `cancel` `bufsize` `dns64` `any` `local` `minimal` `header` `nsid` `chaos` `whoami` `erratic` |
| authoritative | `file` `auto` `secondary` `transfer` `dnssec` `sign` `tsig` |
| server | `bind` `tls` `timeouts` `multisocket` `root` `debug` `metadata` `geoip` `on` `log` `dnstap` `trace` `pprof` |
| backends | `etcd` `grpc` `route53` `azure` `clouddns` |

`import` (files, globs, snippets) and `{$ENV}` / `{%ENV%}` substitution are
handled by the Corefile parser.

The kubernetes plugin has run in a real cluster. On stormcos 11.03
(2026-09-21), under `80-coredns.yaml` against rustkube, it answered
`kubernetes.default.svc.cluster.local` → `10.96.0.1` (stormcos CHANGELOG).
The server's unit tests (`cargo test`, 54 of them) cover the parser,
registry order, rewrite, cache, template, the zone engine, kubernetes name
parsing, and other areas. `cargo test --workspace` adds the test crate's 6. The deployed server is tested from a pod by the test container in
`test/` ([test/README.md](test/README.md)), with short, medium and long
suites per the stormcos test standard (#5). It builds, but it has not yet
run on a test machine.

## Configuration

### Command line

The flag parser is hand-written (not clap) to accept Go's flag syntax. Any
number of leading dashes works, and so do `-flag value` and `-flag=value`.

| flag | alias | meaning | default |
|---|---|---|---|
| `-conf FILE` | | Corefile to load | `Corefile` |
| `-dns.port N` | `-p` | port for `dns://` keys that give none | `53` |
| `-pidfile FILE` | | write the pid; removed on clean exit | none |
| `-quiet` | `-q` | log level `warn`, no startup banner | off |
| `-version` | `-v` | print the version and exit 0 | |
| `-plugins` | | list the directives (`dns.<name>`) and exit 0 | |
| `-h`, `-help` | | usage to stderr, exit 2 | |

The glog flags (`-alsologtostderr`, `-logtostderr`, `-log_dir`,
`-stderrthreshold`, `-vmodule`, `-v_module`, `-log_backtrace_at`) are
accepted and ignored. `-v` means version, so `-v=2` prints the version.
An unknown flag prints `flag provided but not defined` and exits 2.

### Environment

| variable | effect |
|---|---|
| `PORT` | overrides `-dns.port`, even when the flag is given |
| `STORMCOREDNS_LOG`, else `RUST_LOG` | tracing filter (default `info`, or `warn` with `-quiet`); logs go to stdout |
| `{$NAME}` / `{%NAME%}` in the Corefile | substituted at parse time |
| `AZURE_TENANT_ID` `AZURE_CLIENT_ID` `AZURE_CLIENT_SECRET` `AZURE_SUBSCRIPTION_ID` | `azure` defaults |
| `GOOGLE_APPLICATION_CREDENTIALS` | `clouddns` credentials fallback |
| `AWS_ACCESS_KEY_ID` `AWS_SECRET_ACCESS_KEY` `AWS_SESSION_TOKEN`, `HOME` | `route53` credentials |
| `KUBERNETES_SERVICE_HOST`/`_PORT` | `kubernetes` in-cluster client when neither `endpoint` nor `kubeconfig` is set (`KUBECONFIG` is not read, as in CoreDNS) |

### Server-block keys and transports

A key is `[scheme://]zone[:port]`, and several keys can share one block,
separated by spaces or commas. A bare IP or CIDR key becomes its reverse
zone.

| scheme | default port | listeners | needs `tls` plugin |
|---|---|---|---|
| `dns://` (or none) | 53, or `-dns.port`/`PORT` | UDP + TCP | no |
| `tls://` | 853 | TCP (DoT) | yes, or it fails to start |
| `https://` | 443 | TCP, DoH at `/dns-query` (GET `?dns=`, POST `application/dns-message`) | no. Without it, it serves plain HTTP and logs a warning |
| `quic://` | 853 | UDP (DoQ, ALPN `doq`) | yes |
| `grpc://` | 443 | TCP, `coredns.dns.DnsService/Query` | no. Without it, it serves plaintext and logs a warning |

Listeners are grouped one server per (transport, bind address). A query goes
to the longest matching zone, and within that zone to the first config whose
`view` accepts it. If no view accepts, lookup moves on to shorter zones, and
a query that matches no zone at all gets REFUSED. Every socket sets
`SO_REUSEPORT`. For stream transports the idle timeout is 10 s and the
read/write timeouts are 2 s; the `timeouts` plugin changes them.

### Reload

The `reload` plugin (default `30s` interval, `15s` jitter) checks the
Corefile's SHA-256 at random intervals of 15–30 s. SIGHUP and SIGUSR1 also
reload, with or without the plugin. On reload the new instance starts before
the old one stops, and a Corefile that fails to load leaves the old instance
running (`Restart failed: …`, `coredns_reload_failed_total`). SIGINT and
SIGTERM shut down: `health`'s lameduck runs first (DNS keeps answering,
`/health` stays 200, `/ready` turns 503), and then the listeners close. A
reload never waits for lameduck. A failed reload keeps the old instance,
which keeps watching for the next edit.

## Ports and endpoints

These are the defaults when a directive is given with no address:

| directive | default address | paths |
|---|---|---|
| DNS | `:53` UDP + TCP (dual stack `[::]` when IPv6 is available) | |
| `health` | `:8080` | `/health`: 200 `OK` (also during lameduck at exit, as in CoreDNS) |
| `ready` | `:8181` | `/ready`: 200 `OK` once every plugin that reports readiness is ready (kubernetes, route53, azure, clouddns), otherwise 503 with their names |
| `prometheus` | `localhost:9153` (loopback only; write `prometheus :9153` to expose it) | `/metrics` |
| `pprof` | `localhost:6053` | `/debug/pprof/`: process statistics, not Go profiles |

Metrics use CoreDNS's `coredns_*` names and labels: `dns_requests_total`,
`dns_responses_total`, `dns_request_duration_seconds`, and the cache, forward,
kubernetes, acl, template, dnssec and hosts families, plus
`coredns_build_info` and `coredns_plugin_enabled`. There are no `process_*`
metrics. The full list is in [docs/plugins.md](docs/plugins.md#metrics).

## Building and testing

It is a Linux server. The release profile builds one static binary (fat LTO,
stripped, `panic=abort`). `build.rs` compiles `proto/dns.proto` with
tonic-build, which needs `protoc`, and stamps the git SHA into
`coredns_build_info`.

In the stormcentral workflow nothing is built locally. Push, then run:

```bash
sc-build                          # cargo build && cargo test on the build box
sc-build 'cargo test -p stormcoredns cache'
sc-build 'cargo test --locked --workspace && STAGE_ONLY=1 test/build.sh'   # plus the test container
stormcentral test run stormcoredns short --tag <machine> --url http://stormcentral.g8.lo
```

The root package is the workspace's default member, so `cargo build` builds
only the server, as the golden build does. `test/` (`stormcoredns-test`) is
built by `test/build.sh`.

`sc-build` fetches the pushed commit onto `dev.g8.lo` as the unprivileged
build user, builds it in a scratch directory, and deletes that directory. A
failed build files a `build-failure` issue. No step needs root.

Anywhere else, `cargo build --release` then
`./target/release/stormcoredns -conf examples/Corefile.smoke`. That Corefile
serves on 1053 with health, ready and metrics on 18080, 18181 and 19153.

## Shipping

stormcoredns ships as the **`coredns` golden**, a special golden built by
stormcos's builder (`deploy/build-goldens.sh`) in stage mode:

```bash
stormcentral component stage coredns --url http://stormcentral.g8.lo
```

The builder fetches this repo at its pushed commit
(`STORMCOREDNS_SRC=stormcoredns`, stormcentral `src/goldens.rs`) and runs
`cargo build --release --target <musl>`. It stages the binary at
`/stormcoredns` with a `/coredns` symlink, records it as
`stormcoredns@<sha>`, and seals a 32M golden that nodes mount at
`/pallets/coredns`. stormcos's `deploy/manifests/80-coredns.yaml` runs
`command: ["/coredns"]` from `image: coredns`. There is no container image or
registry on this path, and no upstream CoreDNS fallback: if stormcoredns does
not build, the release has no `coredns` golden. How it is deployed is in
[docs/integration.md](docs/integration.md).

For clusters outside stormcos, the `Containerfile` builds a `FROM scratch`
image (`/coredns` plus CA roots), and `deploy/kubernetes/coredns.yaml` is the
upstream manifest with that image. The GitHub releases for v0.1.0 and v0.1.1
include the static binary, an image tarball and `SHA256SUMS`.

## Known gaps

These are the gaps against CoreDNS, each tracked in an issue:

- `dnssec`/`sign`: ECDSA P-256/P-384 and Ed25519 only, no RSA (no OpenSSL
  linked). No NSEC3, no CDS/CDNSKEY.
- `file`/`auto` cannot load zone files that hold RRSIG, NSEC, NSEC3 or
  DNSKEY records, so `sign`'s output cannot be served by `file` (#20). Signed
  zones served through `secondary` get NSEC or NSEC3 denial proofs.
- `trace` logs spans to the tracing subscriber and has no exporter. `pprof`
  serves process statistics rather than Go profiles.
- `kubernetes multicluster` is rejected as not supported.
- Differences from CoreDNS 1.12 left after #15: `template` has no Go
  template control structures or functions (#21), `forward` sends no dnstap
  FORWARDER messages (#22), `route53` has no IRSA/ECS/IMDS credentials (#23),
  `tsig` has only HMAC-SHA256/384/512 and does not sign AXFR (#24). Options
  that are accepted and ignored are listed per plugin in docs/plugins.md.
- Open bugs: #20 (signed zone files).

## Layout

```text
src/main.rs         flags, signals, reload loop
src/corefile/       Caddyfile-v1 lexer, parser (import, snippets, env), Dispenser
src/plugin/         Handler trait, Next, Reply, Request, Controller, registry (plugin.cfg order), replacer
src/server/         config from keys, listener grouping, zone+view dispatch, UDP/TCP/DoT/DoH/DoQ/gRPC, self_lookup
src/plugins/        one module per directive (prometheus is metrics.rs; file/, dnssec/, kubernetes/ are directories)
src/dnsutil/        names, reverse zones, upstream parsing, EDNS0, durations
src/metrics.rs      global registry and core coredns_* collectors
proto/dns.proto     the CoreDNS gRPC service
docs/               architecture, plugin API, per-plugin status, stormcos integration, presentation.md (Marp deck)
examples/           Corefiles (kubernetes, authoritative, smoke) and a zone file
test/               the test container: /test short|medium|long against the cluster DNS (test/README.md)
deploy/kubernetes/  upstream-style manifest for non-stormcos clusters
```

## License

Apache-2.0.
