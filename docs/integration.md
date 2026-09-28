# Integrating stormcoredns (stormcos / rustkube)

How stormcoredns becomes the cluster DNS on a stormcos node, and what it
needs from the node and the API server. Everything here was checked against
this repo's code, and against stormcos (`deploy/build-goldens.sh`,
`deploy/manifests/80-coredns.yaml`, `deploy/image.toml`) and stormcentral
(`src/goldens.rs`) as of 2026-09-27.

## Delivery: the `coredns` golden

No container image or registry is involved. (The mkube registry used for
0.1.0/0.1.1 was retired with mkube on 2026-08-27.)

| | |
|---|---|
| golden | `coredns`, a special golden built by stormcos's builder in stage mode |
| request a build | `stormcentral component stage coredns --url http://stormcentral.g8.lo` after the commit is pushed |
| source | this repo at the pushed commit (`STORMCOREDNS_SRC`), recorded as `stormcoredns@<sha>` |
| build | `cargo build --release --target <musl triple>` on the build box, unprivileged |
| contents | `/stormcoredns` (static binary), `/coredns → stormcoredns`, empty `/etc/coredns/` |
| size | 32M golden |
| on the node | cloned from `pallet:system1/coredns`, mounted at `/pallets/coredns` |

If stormcoredns fails to build, the release has no `coredns` golden. The
builder deliberately has no upstream CoreDNS fallback. The workflow for
goldens is in stormcos `docs/goldens.md`.

## The manifest stormcos runs

`stormcos/deploy/manifests/80-coredns.yaml` is the upstream CoreDNS manifest
with two node-specific changes:

- `image: coredns` (the pallet) and `command: ["/coredns"]`. A golden has
  no OCI image config and so no entrypoint, which makes `command` required.
- `forward . 192.168.8.252` (the g8 MicroDNS) instead of
  `/etc/resolv.conf`. The pod's resolv.conf points back at this Service, and
  forwarding to itself would be a loop.

The Corefile it uses is `errors`, `health { lameduck 5s }`, `ready`,
`kubernetes cluster.local in-addr.arpa ip6.arpa { pods insecure; fallthrough
in-addr.arpa ip6.arpa; ttl 30 }`, `prometheus :9153`, `forward`, `cache 30`,
`loop`, `reload` and `loadbalance`. The `kube-dns` Service is `10.96.0.10`.
The manifest defines no liveness or readiness probes. This matters for now
because of #6: after a reload, `/health` stays at 503 when `lameduck` is set.

stormcoredns forwards to MicroDNS and does not replace it. MicroDNS stays
authoritative for the site zones and owns DHCP and IPAM.

## Ports and endpoints

| port | what | notes |
|---|---|---|
| 53/udp, 53/tcp | DNS | server-block key `.:53`, dual stack when IPv6 is available (#8: IPv4-only after a reload) |
| 8080 | `/health` (`health`) | 200 `OK`. During lameduck it returns 503 while DNS keeps answering |
| 8181 | `/ready` (`ready`) | 200 once the kubernetes watches have synced, otherwise 503 with the plugin name |
| 9153 | `/metrics` (`prometheus :9153`) | `coredns_*` names and labels, no `process_*` metrics. A bare `prometheus` binds `localhost:9153` |

`prometheus :9153` listens on every address, so the pod IP serves
`/metrics`. The node's ironprom (stormcos `deploy/metrics/ironprom-node.yml`)
scrapes it at `10.96.0.10:9153`, but the `kube-dns` Service declares only
port 53, so that target has no backend until stormcos#152 adds a
`metrics` 9153 port.

It needs `NET_BIND_SERVICE` for port 53. It writes nothing to disk (`reload`
only reads the Corefile), so a read-only root works.

## What the kubernetes plugin needs from the API server

It **lists and watches**, cluster-wide:

- `core/v1` `services` and `namespaces` (always), with the `labels` and
  `namespace_labels` selectors applied.
- endpoints (unless `noendpoints`). At startup it asks for the
  `discovery.k8s.io/v1` resource list: if that list contains `endpointslices`,
  it watches EndpointSlices, otherwise core `endpoints`. rustkube therefore
  does not need EndpointSlices. If discovery fails for any reason, it falls
  back to core Endpoints for the life of the instance (#14).
- `core/v1` `pods`, only with `pods verified`. `pods insecure` answers from
  the name alone. `autopath @kubernetes` needs `pods verified` to return
  anything, but it does not start a pod watch itself.

Watches use kube-rs 0.99 `watcher` with its default config: list then watch
by `resourceVersion`. As far as we know that default requests bookmarks and
paginates the initial list, so an API server should honour or ignore
`limit`/`continue` and `allowWatchBookmarks`, and return 410 for an expired
`resourceVersion`.

Client configuration, in order of precedence:

1. `kubeconfig FILE [CONTEXT]`
2. `endpoint URL` with `tls CERT KEY CA` (client certificate). `endpoint
   https://…` without `tls` sends no credentials, skips certificate
   verification and logs a warning.
3. otherwise kube-rs `Config::infer()`: `$KUBECONFIG` or `~/.kube/config` if
   present, else the in-cluster service account and
   `KUBERNETES_SERVICE_HOST`/`_PORT`.

For a static pod with `hostNetwork` and no service account:

```text
kubernetes cluster.local in-addr.arpa ip6.arpa {
    endpoint https://127.0.0.1:6443
    tls /etc/kubernetes/pki/coredns.crt /etc/kubernetes/pki/coredns.key /etc/kubernetes/pki/ca.crt
    pods insecure
    fallthrough in-addr.arpa ip6.arpa
}
```

`/ready` turns 200 when the initial list of every watched kind has completed.
Until then, cluster names get **NXDOMAIN** rather than SERVFAIL (#14), so a
bootstrapper should wait on `/ready` before using DNS. If the client cannot be
built, or discovery errors at startup, the process exits (or, on reload, keeps
the old instance).

RBAC: list/watch on `services`, `endpoints`, `pods`, `namespaces` and
`discovery.k8s.io/endpointslices`. This is the ClusterRole in
`deploy/kubernetes/coredns.yaml` and in stormcos's `80-coredns.yaml`.

## What it serves

- `svc.ns.svc.cluster.local`: A/AAAA for the ClusterIP. For a headless
  service, the ready endpoint IPs.
- `_port._proto.svc.ns.svc.cluster.local`: SRV.
- `<hostname>.svc.ns.svc.cluster.local` for endpoints, or the pod name with
  `endpoint_pod_names`, or the dashed IP.
- `1-2-3-4.ns.pod.cluster.local`: needs `pods insecure|verified` (the default
  is `disabled`).
- PTR for service and ready-endpoint IPs in the reverse zones. There is no pod
  PTR.
- ExternalName → CNAME. For A/AAAA queries whose target is outside the zone,
  the CNAME is chased through the server's own chain (so via `forward`).
- `*`/`any` wildcard labels.
- SOA and NS at `cluster.local`. NS is `ns.dns.cluster.local`, and its glue is
  the kube-dns ClusterIP (or the host's addresses).
- `dns-version.cluster.local` TXT `1.1.0`.
- Default TTL 5, set with `ttl` (0–3600).

## Cilium

Nothing DNS-specific is needed. The `kube-dns` Service name and the
`k8s-app: kube-dns` label are kept, so Cilium's DNS proxy and its default
`toEndpoints` DNS rules work, and so does kubelet `--cluster-dns`.

## Operating it

- **Reload.** Edit the ConfigMap. The `reload` plugin checks the Corefile's
  SHA-256 every 15–30 s. SIGHUP and SIGUSR1 also reload. A bad Corefile keeps
  the old instance and logs `Restart failed: …`. However, automatic reloads
  then stop until a signal arrives (#7).
- **Logs.** Logs go to stdout. `STORMCOREDNS_LOG`/`RUST_LOG` set the filter.
  Add `log` to the block for per-query lines in CoreDNS's common format.
- **Identify the binary.** `/coredns -version` prints `stormcoredns-<ver>
  (CoreDNS-1.12 compatible)`, and `/coredns -plugins` lists the directives.
  `coredns_build_info{revision}` carries the git SHA.

## Outside stormcos

`deploy/kubernetes/coredns.yaml` is the upstream manifest (ServiceAccount,
ClusterRole, ConfigMap, Deployment with `/health` and `/ready` probes,
`kube-dns` Service at `10.96.0.10`). It uses an image built from the
`Containerfile`: `FROM scratch`, with `/coredns` and CA roots, for amd64 or
arm64 via `TARGETARCH`. Build that image and push it to your own registry.
This repo publishes no image registry.
