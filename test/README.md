# stormcoredns-test

stormcoredns's test container, per stormcentral
[`docs/test-standard.md`](https://github.com/glennswest/stormcentral/blob/main/docs/test-standard.md)
(#5). It tests the **cluster DNS of a running node from a pod**, the way every
workload uses it. `cargo test` covers the code itself; this suite covers the
deployed server.

```text
/test short|medium|long
```

It prints one JSON object per test (`{"test", "status", "ms", "detail"}`),
then `{"summary": {…}}`. The exit code is 0 when everything passed, 1 when a
test failed, and 2 when the suite could not run.

## Metadata

```text
suites:    short (< 2 min), medium (< 30 min), long (the night window)
requires:  []            no hardware. Needs the `coredns` golden, which is in
                         every stormcos profile except `storage`; on a node
                         without cluster DNS every suite fails at apex-soa.
privileged: no           a plain pod: no hostNetwork, no node access
api:       namespaced    Services, Endpoints and EndpointSlices in the run's
                         own namespace (the runner's Role); no cluster read
targets:   the cluster DNS server in the pod's /etc/resolv.conf (kube-dns,
           10.96.0.10 on stormcos), port 53 UDP and TCP
external:  none. medium's `forward-answers` sends one query for a
           `.invalid` name (RFC 6761) through the node's upstream
```

The runner's Job does not give it the cluster DNS address, and its Role cannot
read `kube-system`. So it reads `/etc/resolv.conf` like any pod: the
`nameserver` is the kube-dns Service, and the search entry
`<namespace>.svc.<domain>` gives the cluster domain. Everything it checks, it
first creates through the API in its own namespace, labelled
`storm.io/test-run=<run id>`. Each suite deletes what it made, and the runner
deletes the namespace whatever happens.

Endpoint addresses come from the benchmarking range `198.18.0.0/15`, spread by
the run id. They are only data in Endpoints and EndpointSlices; nothing
connects to them. Backends are written as both core Endpoints and an
EndpointSlice, so the test works whichever of the two the plugin watches.

## Suites

**short**: the server is up and does its main job.

| test | checks |
|---|---|
| apex-soa | SOA at `<domain>.` over UDP |
| service-a-udp | a new ClusterIP Service resolves to its ClusterIP within 30 s (the detail reports how long it took) |
| service-a-tcp | the same over TCP |
| service-srv | `_http._tcp.<svc>` → port 80, the Service name |
| nxdomain | an absent Service gets NXDOMAIN with an SOA |
| service-deleted | after the delete, NXDOMAIN within 30 s |

**medium**: the plugin's record set and the server's failure paths.

| test | checks |
|---|---|
| clusterip-a, clusterip-srv-udp-port, clusterip-ptr | A, `_dns._udp` SRV, and PTR of the ClusterIP |
| case-insensitive | an upper-case query answers |
| nodata | an existing name with an absent type gets NOERROR, no answer and an SOA |
| headless-a, endpoint-hostname, headless-srv, endpoint-ptr | a headless Service with named endpoints: A set, `ep-N.<svc>`, SRV targets, PTR |
| endpoints-change, dashed-ip-endpoint | replaced backends show within 30 s; an endpoint with no hostname is named by its dashed address |
| externalname-cname | ExternalName → CNAME |
| pod-by-address | `a-b-c-d.<ns>.pod.<domain>` (`pods insecure`, as stormcos configures it) |
| dns-version, apex-ns | `dns-version` TXT `1.1.0`; NS at the apex |
| udp-truncates, tcp-whole, edns-whole | 100 endpoints: TC over UDP without EDNS; the whole set over TCP and over UDP with EDNS 4096 |
| formerr | a header promising a question it does not carry gets FORMERR |
| forward-answers | a name outside the cluster zone gets an answer other than SERVFAIL within 5 s |
| load | 2000 queries, 50 concurrent: every one correct; reports p50 and p99 |
| deleted-services-vanish | every Service it made is NXDOMAIN within 30 s of its delete |

**long**: overnight waves of Services (see `src/long.rs`). Each wave creates
Services, waits until every one resolves, queries each 10 times with 64 in
flight, deletes them all, and waits until every name is gone. The waves double
from 20 up to 2000, or until the cluster pushes back (a create is refused, or
programming takes more than 2 minutes). After that they alternate between that
ceiling and half of it until 15 minutes before the window ends.

- **Each wave reports:** programming time per Service, query p50/p99,
  answers that were wrong or unresolved, drain time, residue (names still
  resolving after the drain), and the latency of a fixed probe. These come as
  a `wave` object on its line.
- **A wave fails** if an answer was wrong or a name was left behind.
- **The `trend` line fails** if the probe or the per-Service programming time
  becomes more than 3x worse than in wave 1, and names the first wave that
  did.

## Build and run

```bash
sc-build 'cargo test -p stormcoredns-test'          # the crate's unit tests
sc-build 'STAGE_ONLY=1 test/build.sh'               # the static binary, as the runner builds it
stormcentral test run stormcoredns short --tag <machine>   # a real run on a test machine
```

The runner runs `test/build.sh` on the build box (with `CARGO_TARGET_DIR` set),
then `podman build -f test/Containerfile .`. It pushes the image to the
machine's sbregistry as `test-stormcoredns-<suite>:<commit12>` and runs it
as a Job.

To run the suites by hand against another server, set
`STORMCOREDNS_TEST_DNS` (`host[:port]`) and `STORMCOREDNS_TEST_DOMAIN`.
