# Writing a plugin

A plugin is a module under `src/plugins/` (a file, or a directory like
`file/`, `dnssec/`, `kubernetes/`) with a `setup` function. Add `pub mod
<name>;` to `src/plugins/mod.rs` and register the directive in
`src/plugin/registry.rs` at its `plugin.cfg` position. The module name
usually matches the directive; `prometheus` is `metrics.rs`, `loop` is
`r#loop`.

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
`next_line`, `next_block`, `val`, `remaining_args`,
`remaining_args_until_brace`, `args(n) -> Option<Vec<String>>`, `skip_block`,
`line`, `file`, `arg_err`, `errf`, `err`, `syntax_err`). Setup errors that do
not start with `plugin/` are prefixed with `plugin/<name>: `. The Controller
adds:

* `c.config` — the `ServerConfig` being built (`zone`, `port`,
  `transport`, `root`, `tls`, `listen_hosts`, `view_name`, `filter`,
  timeouts, `num_sockets`, `tsig_secrets`, `values`; `values["corefile"]`
  is the Corefile path).
* `c.key`, `c.server_block_keys`, `c.zone()`, `c.is_first_key()`,
  `c.plugin_err(...)`.
* `c.add_plugin(handler)` — append to the chain (order is fixed by the registry).
* `c.on_startup(hook)`, `c.on_shutdown(hook)` —
  `config::Hook = Box<dyn FnOnce() -> BoxFuture<'static, Result<()>> + Send + Sync>`.
  A failing startup hook aborts the start (or the reload).
* `c.on_restart(hook)`, `c.on_restart_failed(hook)` —
  `config::RestartHook = Arc<dyn Fn() -> BoxFuture<'static, Result<()>> + Send + Sync>`,
  run on every reload attempt of the instance that registered them.
  `on_restart` hooks run before the new instance is built; an error aborts
  that reload and keeps the running instance. `on_restart_failed` hooks
  run when a reload fails. No plugin registers either yet.
* `c.once_per_server_block(|c| ...)` — run once even when the block has
  several keys.
* `c.server_block_zones()`, `c.origins_from_args_or_server_block(args)`.
* `crate::plugins::wire::register(c, |cfg| ...)` — run once every
  config's chain is finalised (in `plugins::post_finalize`, before the
  listeners bind), to find sibling handlers (`cfg.handler("kubernetes")`).
  Used by autopath, k8s_external, transfer and metadata.

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
        let mut m = req.new_reply();                   // id, opcode, question, RD, CD; EDNS 4096 if the query had EDNS
        m.set_authoritative(true);
        m.add_answer(/* Record */);
        Ok(Reply::Msg(m))
    }
}
```

Optional hooks with defaults: `ready()` (readiness for `ready`),
`autopath(req)`, `transfer(zone)` (records for AXFR), `external_addrs(ns,
svc)`, `external_reverse(ip)`, `metadata(req)`.

The `cancel` deadline is `req.deadline` (`req.is_cancelled()` once it has
passed). The chain already runs under `cancel`'s timeout; a plugin that
waits on the network should also stop retrying once it passes, as
`forward` does.

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

`req.msg` is the query (`hickory_proto::op::Message`); `req.name()`
(takes `&mut self`, cached — call `req.clear_name_cache()` after rewriting
the question),
`req.qname()`, `req.qtype()`, `req.qclass()`, `req.ip()`, `req.port()`,
`req.proto`, `req.local_ip()`/`local_port()`, `req.size()` (EDNS size, 512
floor, 65535 on streams), `req.do_bit()`, `req.tls_server_name`, `req.http`
(DoH), `req.tsig_verified`, `req.ext` (typed extensions),
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
