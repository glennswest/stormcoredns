# Architecture

stormcoredns keeps CoreDNS's shape: a Corefile is parsed into server
blocks, every directive's `setup` runs against the block's config, the
resulting handlers are sorted into `plugin.cfg` order, and each incoming
query walks that chain until a plugin answers.

```text
Corefile ──lex/parse──▶ ServerBlock{keys, directives}
                              │  one ServerConfig per key
                              ▼
                     registry::ORDER (plugin.cfg)
                     for directive in ORDER:
                        for block: for key: setup(Controller)
                              │
                              ▼
                     ServerConfig{zone, port, transport, plugins[], tls, view filter, hooks}
                              │  group by (transport, bind addr)
                              ▼
                     Server{zones: zone → [ZoneEntry{config, chain}]}
                              │
        UDP ─┐                ▼
        TCP ─┤        lookup(qname): longest zone suffix, then view filter
        TLS ─┼──▶     Next::new(&chain).serve(&mut req) ──▶ Reply
        DoH ─┤                │
        DoQ ─┤                ▼
       gRPC ─┘        encode (EDNS size / TC), write
```

## Corefile

`src/corefile/` ports caddy v1's lexer and parser: tokens carry line
numbers so `NextArg`/`NextLine`/`NextBlock` semantics are identical,
`import` splices files/globs/snippets (inside a server block only; paths are
relative to the Corefile's directory; nesting is capped at 20), `{$ENV}` and
`{%ENV%}` expand, keys may be comma-separated, and a brace-less block is
accepted as the first (and then only) block. `Dispenser` is the token cursor and
`Controller` wraps it with the config being built (`c.config`), the
current key, `once_per_server_block`, and startup/shutdown hooks.

## The chain

`plugin::Handler` is the plugin trait: `serve_dns(&self, req, next)`.
`Next` is a cursor over the remaining handlers; calling `next.serve(req)`
runs the rest of the chain and hands the *response back as a value*. That
replaces CoreDNS's `ResponseWriter` wrappers: a plugin that wants to
observe or edit the response (cache, rewrite, dnssec, loadbalance, minimal,
header, log, prometheus) inspects what `next.serve` returns.

`Reply` is `Msg(Message)`, `Rcode(code)` (nothing written; the server
answers with the code), `Drop` (send nothing) or `Multi(Vec<Message>)`
(zone transfers — every message is written on TCP/DoT; UDP, DoH, DoQ and
gRPC send only the first). Errors are `PluginError{plugin, rcode, source}`;
`errors` logs them, the server answers with `rcode`.

Cross-plugin contracts that CoreDNS expresses as Go interfaces are default
methods on `Handler`: `ready()`, `autopath()`, `transfer()`,
`external_addrs()`, `external_reverse()`, `metadata()`. Because a plugin's `setup` runs before later plugins
exist, `plugins::wire::register` defers the lookup of a sibling handler
until every config's chain is finalised (`plugins::post_finalize`, before
the listeners bind) — CoreDNS's `c.OnStartup` +
`config.Handler("kubernetes")`.

Unknown directives are rejected before any `setup` runs. A panic inside a
plugin is caught: the client gets SERVFAIL and `coredns_panics_total`
increments.

## Servers

A server-block key is `[scheme://]zone[:port]` (`src/server/config.rs`):
`dns` (53, UDP+TCP), `tls` (853, DoT), `https` (443, DoH at `/dns-query`),
`quic` (853, DoQ), `grpc` (443, `coredns.dns.DnsService/Query`). `tls://`
and `quic://` need the `tls` plugin; `https://` and `grpc://` fall back to
plaintext with a warning. `-dns.port`/`PORT` only change `dns://` keys
without a port.

One `Server` per (transport, bind address). Zone dispatch is the CoreDNS
algorithm: strip labels from the query name until a configured zone
matches, then take the first config whose `view` expression accepts the
request (view configs sort ahead of the catch-all); if none accepts, keep
stripping; no zone at all is REFUSED. View filters run here, before the
chain. As in CoreDNS, a config's `metadata` plugin collects the providers'
labels into the request before its filter runs, so `metadata()` in a view
expression works, and the chain sees the same labels.

Listeners bind with `SO_REUSEPORT` (UDP sockets also get 4 MiB buffers;
IPv6 sockets are dual-stack), so a reload starts the new instance before
the old one stops. `:port` binds `[::]:port` (dual stack) whenever the host
can open IPv6 sockets (probed once on `[::]:0`), else `0.0.0.0:port`; the
real port is never probe-bound, since the old instance holds it during a
reload (#8). Stream transports pipeline: each query is answered as
it completes, writes are serialised through a channel; idle 10 s, read 3 s,
write 5 s (CoreDNS's defaults) unless `timeouts` says otherwise. AXFR replies are built in memory
and written as several messages.

Before the chain: malformed → FORMERR (or nothing if the ID is unreadable),
EDNS version ≠ 0 → BADVERS, no question → REFUSED. After it, replies are
encoded at `req.size()` and truncated (TC) to fit.

`server::self_lookup` resolves a name through the server's own chain —
what CoreDNS does with `upstream` by querying itself over loopback — with a
depth limit of 8, preferring the server the request arrived on. It is used
for external CNAME targets (`file`, `kubernetes`, `etcd`), `dns64`, and
`rewrite cname`.

## Lifecycle

`Instance::start` builds configs, finalises chains, runs
`plugins::post_finalize` (wiring, ready's plugin list, health, metrics),
binds every listener, runs startup hooks (a failing hook aborts the start),
then serves. `Instance::stop` runs shutdown hooks, then cancels
listeners, waiting up to the servers' `graceful_timeout` (5 s, CoreDNS's
fixed grace time) for them all. At process exit `Instance::stop_final` first
runs the final-shutdown hooks (CoreDNS `OnFinalShutdown`): `ready` turns
`/ready` to 503 and `health`'s lameduck waits while DNS keeps answering and
`/health` stays 200. A reload never runs them, so it is not delayed by
lameduck (#6). `reload` hashes the parsed Corefile (SHA-512) and, on change,
signals the main loop; SIGHUP and SIGUSR1 do the same. The main loop runs the old instance's `restart` hooks (an error aborts the
reload), starts a new instance and stops the old one; a failed reload keeps
the old instance, increments `coredns_reload_failed_total` and runs its
`restart_failed` hooks. Both kinds run on every attempt (no plugin
registers one today). Open bug in this
path: #7 (the watcher does not re-arm after a failed reload).

The HTTP endpoints (`health`, `ready`, `prometheus`, `pprof`) share a
registry keyed by address; on reload the new instance takes the listener
over from the old one.

## Metrics

`metrics.rs` owns the global Prometheus registry and the core
collectors (`coredns_dns_*`, `panics_total`, `plugin_enabled`,
`build_info`, `health_*`, `reload_*`); the `prometheus` plugin does the
per-request counting. Plugins register their own with the names CoreDNS
uses (`coredns_cache_*`, `coredns_forward_*`, `coredns_kubernetes_*` …) so
dashboards and alerts carry over. There are no `process_*` metrics. The
full list is in [plugins.md](plugins.md#metrics).
