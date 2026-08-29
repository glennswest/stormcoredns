//! `header` — set or clear header flags on responses (and queries).
//!
//! ```text
//! header {
//!     response set aa ra
//!     response clear rd
//!     query set cd
//! }
//! ```
//! Flags: `aa`, `ra`, `rd`, `ad`, `cd`, `tc`. A bare `set`/`clear` line means `response`.

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use hickory_proto::op::Message;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flag {
    Aa,
    Ra,
    Rd,
    Ad,
    Cd,
    Tc,
}

impl Flag {
    fn parse(s: &str) -> Option<Flag> {
        Some(match s {
            "aa" => Flag::Aa,
            "ra" => Flag::Ra,
            "rd" => Flag::Rd,
            "ad" => Flag::Ad,
            "cd" => Flag::Cd,
            "tc" => Flag::Tc,
            _ => return None,
        })
    }
    fn apply(&self, m: &mut Message, v: bool) {
        match self {
            Flag::Aa => m.set_authoritative(v),
            Flag::Ra => m.set_recursion_available(v),
            Flag::Rd => m.set_recursion_desired(v),
            Flag::Ad => m.set_authentic_data(v),
            Flag::Cd => m.set_checking_disabled(v),
            Flag::Tc => m.set_truncated(v),
        };
    }
}

pub struct Header {
    query: Vec<(Flag, bool)>,
    response: Vec<(Flag, bool)>,
}

#[async_trait]
impl Handler for Header {
    fn name(&self) -> &'static str {
        "header"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        for (f, v) in &self.query {
            f.apply(&mut req.msg, *v);
        }
        let mut r = next.serve(req).await?;
        if let Some(m) = r.msg_mut() {
            for (f, v) in &self.response {
                f.apply(m, *v);
            }
        }
        Ok(r)
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/header: this plugin can only be used once per Server Block"));
        }
        if c.next_arg() {
            return Err(c.arg_err());
        }
        let mut h = Header { query: Vec::new(), response: Vec::new() };
        while c.next_block() {
            let mut toks = vec![c.val().to_string()];
            toks.extend(c.remaining_args());
            let (target, rest) = match toks[0].as_str() {
                "query" => (&mut h.query, &toks[1..]),
                "response" => (&mut h.response, &toks[1..]),
                _ => (&mut h.response, &toks[..]),
            };
            if rest.is_empty() {
                return Err(c.errf("header: expected set or clear"));
            }
            let v = match rest[0].as_str() {
                "set" => true,
                "clear" => false,
                o => return Err(c.errf(format!("unknown action '{}'", o))),
            };
            if rest.len() < 2 {
                return Err(c.errf("header: at least one flag is required"));
            }
            for f in &rest[1..] {
                let flag = Flag::parse(f).ok_or_else(|| c.errf(format!("unknown flag '{}'", f)))?;
                target.push((flag, v));
            }
        }
        c.add_plugin(Arc::new(h));
    }
    Ok(())
}
