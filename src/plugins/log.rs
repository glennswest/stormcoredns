//! `log` — query logging to stdout.
//!
//! ```text
//! log [NAMES...] [FORMAT] {
//!     class CLASSES...
//! }
//! ```
//! FORMAT is `common` (default), `combined`, or a custom `{placeholder}`
//! string. CLASSES: `all`, `success`, `denial`, `error`.

use crate::plugin::replacer::{Replacer, COMBINED_LOG_FORMAT, COMMON_LOG_FORMAT};
use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Class {
    All,
    Success,
    Denial,
    Error,
}

struct Rule {
    zones: Vec<String>,
    format: Replacer,
    classes: HashSet<Class>,
}

pub struct Log {
    rules: Vec<Rule>,
}

fn classify(rcode: ResponseCode, msg: Option<&hickory_proto::op::Message>) -> Class {
    match rcode {
        ResponseCode::NoError => {
            if let Some(m) = msg {
                if m.answers().is_empty() {
                    return Class::Denial; // NODATA
                }
            }
            Class::Success
        }
        ResponseCode::NXDomain => Class::Denial,
        ResponseCode::ServFail | ResponseCode::NotImp | ResponseCode::Refused | ResponseCode::FormErr => Class::Error,
        _ => Class::Error,
    }
}

#[async_trait]
impl Handler for Log {
    fn name(&self) -> &'static str {
        "log"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let name = req.name();
        let rule = self
            .rules
            .iter()
            .filter(|r| crate::plugin::zones_match(&r.zones, &name).is_some())
            .max_by_key(|r| crate::plugin::zones_match(&r.zones, &name).map(|z| z.len()).unwrap_or(0));
        let Some(rule) = rule else {
            return next.serve(req).await;
        };
        let r = next.serve(req).await;
        let (rcode, reply, err_rcode) = match &r {
            Ok(rep) => (rep.rcode(), Some(rep), None),
            Err(e) => (e.rcode, None, Some(e.rcode)),
        };
        let class = classify(rcode, reply.and_then(|r| r.msg()));
        if rule.classes.contains(&Class::All) || rule.classes.contains(&class) {
            let line = rule.format.replace(req, reply, err_rcode);
            println!("[INFO] {}", line);
        }
        let _: Option<&Reply> = reply;
        r
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut rules = Vec::new();
    while c.next() {
        let mut args = c.remaining_args_until_brace();
        let mut format = COMMON_LOG_FORMAT.to_string();
        let mut zones: Vec<String> = Vec::new();
        // the last arg may be a format
        if !args.is_empty() {
            let last = args.last().unwrap().clone();
            let is_format = last == "common" || last == "combined" || last.contains('{');
            if is_format {
                format = match last.as_str() {
                    "common" => COMMON_LOG_FORMAT.to_string(),
                    "combined" => COMBINED_LOG_FORMAT.to_string(),
                    f => f.to_string(),
                };
                args.pop();
            }
        }
        if args.is_empty() {
            zones = c.server_block_zones();
        } else {
            for a in &args {
                zones.extend(crate::dnsutil::normalize_zone(a)?);
            }
        }
        let mut classes: HashSet<Class> = HashSet::new();
        while c.next_block() {
            match c.val() {
                "class" => {
                    let cls = c.remaining_args();
                    if cls.is_empty() {
                        return Err(c.arg_err());
                    }
                    for cl in cls {
                        classes.insert(match cl.as_str() {
                            "all" => Class::All,
                            "success" => Class::Success,
                            "denial" => Class::Denial,
                            "error" => Class::Error,
                            other => return Err(c.errf(format!("unknown class '{}'", other))),
                        });
                    }
                }
                other => return Err(c.errf(format!("unknown property '{}'", other))),
            }
        }
        if classes.is_empty() {
            classes.insert(Class::All);
        }
        rules.push(Rule { zones, format: Replacer::new(&format), classes });
    }
    c.add_plugin(Arc::new(Log { rules }));
    Ok(())
}
