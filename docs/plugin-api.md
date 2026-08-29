# Writing a plugin

A plugin is one module in `src/plugins/<name>.rs` with a `setup` function,
registered in `src/plugin/registry.rs` at its `plugin.cfg` position.

## setup

```rust
use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use std::sync::Arc;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {                                   // once per occurrence of the directive
        let args = c.remaining_args_until_brace();     // same-line arguments
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut ttl = 30;
        while c.next_block() {                         // { ... } lines
            match c.val() {
                "ttl" => {
                    let a = c.remaining_args();
                    if a.len() != 1 { return Err(c.arg_err()); }
                    ttl = a[0].parse().map_err(|_| c.errf(format!("bad ttl {}", a[0])))?;
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        c.add_plugin(Arc::new(MyPlugin { zones, ttl }));
    }
    Ok(())
}
```

`Controller` derefs to the caddy `Dispenser` (`next`, `next_arg`,
`next_line`, `next_block`, `val`, `args`, `remaining_args`, `arg_err`,
`errf`) and adds:

* `c.config` — the `ServerConfig` being built (`zone`, `port`, `root`,
  `tls`, `listen_hosts`, `view_name`, `filter`, timeouts, `values`).
* `c.add_plugin(handler)` — append to the chain (order is fixed by the registry).
* `c.on_startup(hook)`, `c.on_shutdown(hook)`, `c.on_restart_failed(hook)`
  — `Box<dyn FnOnce() -> BoxFuture<Result<()>> + Send + Sync>`.
* `c.once_per_server_block(|c| ...)` — run once even when the block has
  several keys.
* `c.server_block_zones()`, `c.origins_from_args_or_server_block(args)`.
* `crate::plugins::wire::register(c, |cfg| ...)` — run after the block's
  chain is complete, to find sibling handlers (`cfg.handler("kubernetes")`).

## Handler

```rust
#[async_trait]
impl Handler for MyPlugin {
    fn name(&self) -> &'static str { "myplugin" }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();                        // lowercase FQDN
        if crate::plugin::zones_match(&self.zones, &qname).is_none() {
            return next.serve(req).await;              // not ours
        }
        let mut m = req.new_reply();                   // id, question, RD, EDNS mirrored
        m.set_authoritative(true);
        m.add_answer(/* Record */);
        Ok(Reply::Msg(m))
    }
}
```

Optional hooks with defaults: `ready()` (readiness for `ready`),
`health()`, `autopath(req)`, `transfer(zone)`, `external_addrs(ns, svc)`,
`external_reverse(ip)`, `metadata(req)`.

To see or change the response of the plugins after you:

```rust
let mut r = next.serve(req).await?;
if let Some(m) = r.msg_mut() { /* edit */ }
Ok(r)
```

To fail: `Err(crate::plugin::error("myplugin", anyhow!("...")))` — the
client gets SERVFAIL and `errors` logs it; `.with_rcode(...)` changes the
code.

## Request

`req.msg` is the query (`hickory_proto::op::Message`); `req.name()`,
`req.qname()`, `req.qtype()`, `req.qclass()`, `req.ip()`, `req.port()`,
`req.proto`, `req.size()` (client buffer size), `req.do_bit()`,
`req.server`/`req.zone`/`req.view` (metrics labels), `req.metadata`
(labels from `metadata` providers), `req.raw` (wire bytes),
`req.new_with_question(name, qtype)` for sub-queries, and
`crate::server::self_lookup(req, name, qtype)` to resolve through the
server's own chain.

## Metrics

Create collectors with `once_cell::sync::Lazy` and register them through
`crate::metrics::register(Box::new(c.clone()))`; use the CoreDNS metric
name (`coredns_<plugin>_..._total`) and labels.

## Tests

`Request::for_test(name, qtype)` builds a UDP request from 127.0.0.1;
`Next::new(&chain).serve(&mut req).await` runs a chain of `Arc<dyn
Handler>` without a server. See `src/plugins/cache.rs` or
`src/plugins/kubernetes/mod.rs` for examples.
