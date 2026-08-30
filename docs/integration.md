# Integrating stormcoredns (stormcos / rustkube / mkube)

Everything a node OS or cluster bootstrapper needs to run stormcoredns as
the cluster DNS. It is a drop-in for CoreDNS: same image entrypoint
(`/coredns`), same flags, same Corefile, same ports and probes.

## Image

| | |
|---|---|
| registry | `192.168.200.3:5000/stormcoredns:0.1.1` (also `:latest`) — the mkube registry; pushed from dev with `podman push --tls-verify=false` |
| base | `scratch`: one static musl binary at `/coredns` + `/etc/ssl/certs/ca-certificates.crt` |
| size | 15.1 MB |
| arch | linux/amd64 (the `Containerfile` honours `TARGETARCH`; build with `--platform linux/arm64` for MikroTik/ARM nodes) |
| entrypoint | `/coredns` — pass `-conf /etc/coredns/Corefile` |
| user | runs as root by default; only `NET_BIND_SERVICE` is needed for :53 |

Release assets (https://github.com/glennswest/stormcoredns/releases/tag/v0.1.1):
`stormcoredns-0.1.1-image.tar.gz` (docker-archive of the image, load with
`podman load -i` / `docker load -i`, or feed it to the stormcos image store),
`stormcoredns-0.1.1-linux-amd64.tar.gz` (the static binary alone) and
`SHA256SUMS`.

There is no shell, no libc and no writable filesystem requirement
(`readOnlyRootFilesystem: true` works; `reload` only reads the Corefile).

## Ports and endpoints

| port | what | notes |
|---|---|---|
| 53/udp, 53/tcp | DNS | server-block key `.:53` |
| 8080 | `/health` | liveness; `lameduck 5s` keeps DNS answering while it returns 503 during shutdown |
| 8181 | `/ready` | readiness; 200 once the `kubernetes` watches have synced, otherwise 503 with the plugin name |
| 9153 | `/metrics` | Prometheus, `coredns_*` names/labels (existing dashboards apply) |

## Kubernetes manifest

`deploy/kubernetes/coredns.yaml` is the upstream CoreDNS manifest with
the image swapped: ServiceAccount, ClusterRole (list/watch on services,
endpoints, endpointslices, pods, namespaces), ConfigMap, Deployment,
`kube-dns` Service. Set `spec.clusterIP` to the cluster DNS IP the
kubelets are given (`--cluster-dns`).

```bash
kubectl apply -f deploy/kubernetes/coredns.yaml
kubectl -n kube-system rollout status deploy/coredns
```

For a static pod on a control-plane node (stormcos style, no scheduler
yet), use the same container spec with `hostNetwork: true` and mount the
Corefile from disk; point the `kubernetes` plugin at the API server
explicitly since there is no in-cluster service account:

```text
kubernetes cluster.local in-addr.arpa ip6.arpa {
    endpoint https://127.0.0.1:6443
    tls /etc/kubernetes/pki/coredns.crt /etc/kubernetes/pki/coredns.key /etc/kubernetes/pki/ca.crt
    pods insecure
    fallthrough in-addr.arpa ip6.arpa
}
```

or `kubeconfig /etc/kubernetes/coredns.kubeconfig`. Without either option
the plugin uses the in-cluster service-account token and
`KUBERNETES_SERVICE_HOST`/`_PORT`, exactly like CoreDNS.

## API server requirements (rustkube)

The `kubernetes` plugin only **lists and watches**:

- `core/v1`: `services`, `namespaces`, `endpoints`, and `pods` (pods only
  when `pods verified` or `autopath @kubernetes` is configured);
- `discovery.k8s.io/v1`: `endpointslices` — **optional**. At startup it asks
  the API for the `discovery.k8s.io/v1` resource list; if `endpointslices`
  is not there it watches core `endpoints` instead. rustkube does not need
  to implement EndpointSlices for cluster DNS to work.

Watch semantics needed: the standard list + watch with `resourceVersion`
and bookmark-free streams (kube-rs `watcher` with the list-watch
strategy; `sendInitialEvents`/streaming lists are not required).

Readiness (`/ready`) turns 200 after the initial list of every watched
kind completes, so a bootstrapper can gate "DNS is up" on that endpoint.

## Cilium

Nothing DNS-specific is needed. Cilium's DNS proxy (FQDN policies) sits
between pods and the `kube-dns` Service; it sees identical responses.
The `kube-dns` Service name and `k8s-app: kube-dns` label are kept so
Cilium's default `toEndpoints` DNS rules and the `--cluster-dns` kubelet
setting keep working.

## What it serves (schema)

`svc.ns.svc.cluster.local` A/AAAA (ClusterIP; endpoint IPs for headless),
`_port._proto.svc.ns.svc.cluster.local` SRV, `<hostname|pod|dashed-ip>.svc.ns.svc.cluster.local`
for endpoints, `1-2-3-4.ns.pod.cluster.local` (pods), PTR for service and
endpoint IPs in the reverse zones, ExternalName → CNAME (chased through
`forward`), SOA/NS at `cluster.local`, `dns-version.cluster.local` TXT.

## Operating it

- Reload: edit the ConfigMap; the `reload` plugin picks it up within 30 s
  (±15 s jitter). `SIGHUP`/`SIGUSR1` also reload. A bad Corefile keeps the
  old instance running and logs `Restart failed`.
- Logs go to stdout; add `log` to the server block for per-query lines in
  CoreDNS's common format.
- Query the plugin list with `/coredns -plugins`, the version with `-version`.

## Building it yourself

```bash
ssh root@dev.g8.lo 'cd /root/stormcoredns && git pull && podman build -t localhost/stormcoredns:dev .'
```

Multi-arch: `podman build --platform linux/arm64 ...` (needs
`qemu-user-static` on the builder) then `podman manifest` to combine.
