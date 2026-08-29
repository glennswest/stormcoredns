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

`src/corefile/` is a faithful port of caddy v1's lexer and parser:
tokens carry line numbers so `NextArg`/`NextLine`/`NextBlock` semantics are
identical, `import` splices files/globs/snippets, `{$ENV}` expands, and a
single brace-less block is accepted. `Dispenser` is the token cursor and
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
(zone transfers). Errors are `PluginError{plugin, rcode, source}`;
`errors` logs them, the server answers with `rcode`.

Cross-plugin contracts that CoreDNS expresses as Go interfaces are default
methods on `Handler`: `ready()`, `autopath()`, `transfer()`,
`external_addrs()`, `metadata()`. Because a plugin's `setup` runs before
later plugins exist, `plugins::wire::register` defers the lookup of a
sibling handler until the block's chain is complete (CoreDNS's
`c.OnStartup` + `config.Handler("kubernetes")`).

## Servers

One `Server` per (transport, bind address). Zone dispatch is the CoreDNS
algorithm: strip labels from the query name until a configured zone
matches, then take the first config whose `view` expression accepts the
request. Listeners bind with `SO_REUSEPORT`, so a reload starts the new
instance before the old one stops. Stream transports pipeline: each
query is answered as it completes, writes are serialised through a
channel. AXFR replies are streamed as multiple messages.

`server::self_lookup` resolves a name through the server's own chain —
what CoreDNS does with `upstream` by querying itself over loopback — and
is used for external CNAME targets (`file`, `kubernetes`), `dns64`, and
`rewrite cname`.

## Lifecycle

`Instance::start` builds configs, binds every listener, runs startup
hooks, then serves. `Instance::stop` runs shutdown hooks first (so
`health`'s lameduck keeps answering DNS while `/health` reports 503), then
cancels listeners. `reload` hashes the Corefile and, on change, signals
the main loop, which starts a new instance and stops the old one; a failed
reload keeps the old instance and runs `restart_failed` hooks.

## Metrics

`metrics.rs` owns the global Prometheus registry and the core
`coredns_dns_*` collectors; plugins register their own with the same
names CoreDNS uses (`coredns_cache_*`, `coredns_forward_*`,
`coredns_kubernetes_*` …) so dashboards and alerts carry over.
