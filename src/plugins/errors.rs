//! `errors` — logs errors returned by later plugins, optionally
//! consolidating repeated messages.
//!
//! ```text
//! errors {
//!     consolidate DURATION REGEXP [LEVEL]
//!     stacktrace
//! }
//! ```

use crate::plugin::{Controller, DnsResult, Handler, Next, Request};
use async_trait::async_trait;
use parking_lot::Mutex;
use regex::Regex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Error,
    Warning,
    Info,
    Debug,
}

struct Pattern {
    period: Duration,
    re: Regex,
    level: Level,
    count: Mutex<(u64, Option<Instant>)>,
}

pub struct Errors {
    patterns: Vec<Arc<Pattern>>,
    stacktrace: bool,
}

impl Errors {
    fn log(&self, req: &Request, e: &crate::plugin::PluginError) {
        let text = format!(
            "{} {} {}: {}",
            req.msg.id(),
            req.name_uncached(),
            req.type_str(),
            e
        );
        for p in &self.patterns {
            if p.re.is_match(&e.to_string()) {
                let mut c = p.count.lock();
                c.0 += 1;
                if c.1.is_none() {
                    // first occurrence starts a period; the summary line is
                    // printed when the period ends
                    c.1 = Some(Instant::now());
                    let p2 = p.clone();
                    let sample = e.to_string();
                    tokio::spawn(async move {
                        tokio::time::sleep(p2.period).await;
                        let (n, _) = {
                            let mut c = p2.count.lock();
                            let v = *c;
                            *c = (0, None);
                            v
                        };
                        let msg = format!("{} errors like '{}' occurred in last {}", n, sample, crate::plugin::replacer::format_duration(p2.period));
                        match p2.level {
                            Level::Error => tracing::error!("plugin/errors: {}", msg),
                            Level::Warning => tracing::warn!("plugin/errors: {}", msg),
                            Level::Info => tracing::info!("plugin/errors: {}", msg),
                            Level::Debug => tracing::debug!("plugin/errors: {}", msg),
                        }
                    });
                }
                return;
            }
        }
        if self.stacktrace {
            tracing::error!("plugin/errors: {}\n{}", text, std::backtrace::Backtrace::force_capture());
        } else {
            tracing::error!("plugin/errors: {}", text);
        }
    }
}

#[async_trait]
impl Handler for Errors {
    fn name(&self) -> &'static str {
        "errors"
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let r = next.serve(req).await;
        if let Err(e) = &r {
            self.log(req, e);
        }
        r
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut e = Errors { patterns: Vec::new(), stacktrace: false };
    let mut count = 0;
    while c.next() {
        count += 1;
        if count > 1 {
            return Err(c.errf("plugin/errors: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        if !args.is_empty() {
            // legacy `errors stdout` form
            if args.len() == 1 && args[0] == "stdout" {
            } else {
                return Err(c.arg_err());
            }
        }
        while c.next_block() {
            match c.val() {
                "stacktrace" => e.stacktrace = true,
                "consolidate" => {
                    let a = c.remaining_args();
                    if a.len() < 2 || a.len() > 3 {
                        return Err(c.arg_err());
                    }
                    let period = crate::dnsutil::parse_duration(&a[0])?;
                    let re = Regex::new(&a[1]).map_err(|err| c.errf(format!("invalid regexp {}: {}", a[1], err)))?;
                    let level = match a.get(2).map(|s| s.as_str()).unwrap_or("error") {
                        "error" => Level::Error,
                        "warning" => Level::Warning,
                        "info" => Level::Info,
                        "debug" => Level::Debug,
                        other => return Err(c.errf(format!("unknown log level {}", other))),
                    };
                    e.patterns.push(Arc::new(Pattern { period, re, level, count: Mutex::new((0, None)) }));
                }
                other => return Err(c.errf(format!("unknown property '{}'", other))),
            }
        }
    }
    c.add_plugin(Arc::new(e));
    Ok(())
}
