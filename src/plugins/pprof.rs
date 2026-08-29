//! `pprof [ADDRESS] { block RATE }` — the `/debug/pprof/` endpoint
//! (default `localhost:6053`). Go runtime profiles do not exist in a Rust
//! process; the endpoint serves process statistics (RSS, threads, file
//! descriptors, uptime) in the same place so tooling and runbooks that
//! expect it keep working.

use crate::plugin::Controller;
use crate::server::http_util::{self, Endpoints};
use once_cell::sync::Lazy;
use std::time::Instant;

static ENDPOINTS: Lazy<Endpoints> = Lazy::new(Endpoints::default);
static START: Lazy<Instant> = Lazy::new(Instant::now);

fn proc_stats() -> String {
    let mut out = String::new();
    out.push_str(&format!("uptime_seconds: {}\n", START.elapsed().as_secs()));
    out.push_str(&format!("pid: {}\n", std::process::id()));
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS") || line.starts_with("VmHWM") || line.starts_with("Threads") || line.starts_with("VmSize") {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
        out.push_str(&format!("open_fds: {}\n", fds.count()));
    }
    out
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut addr = "localhost:6053".to_string();
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/pprof: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        match args.len() {
            0 => {}
            1 => addr = args[0].clone(),
            _ => return Err(c.arg_err()),
        }
        while c.next_block() {
            match c.val() {
                "block" => {
                    let a = c.remaining_args();
                    if a.len() != 1 || a[0].parse::<u64>().is_err() {
                        return Err(c.errf("block RATE expected"));
                    }
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
    }
    Lazy::force(&START);
    c.once_per_server_block(|c| {
        ENDPOINTS.install(c, &addr, |req| async move {
            match req.uri().path() {
                "/debug/pprof/" | "/debug/pprof" => http_util::with_type(
                    200,
                    "text/html; charset=utf-8",
                    "<html><body><h1>stormcoredns /debug/pprof/</h1><p>Go runtime profiles are not available in this build.</p><ul><li><a href=\"/debug/pprof/stats\">stats</a> — process statistics</li><li><a href=\"/debug/pprof/goroutine\">goroutine</a> — thread count</li></ul></body></html>",
                ),
                "/debug/pprof/stats" | "/debug/pprof/heap" | "/debug/pprof/allocs" => http_util::text(200, proc_stats()),
                "/debug/pprof/goroutine" | "/debug/pprof/threadcreate" => {
                    let threads = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("Threads")).map(|l| l.to_string())).unwrap_or_else(|| "Threads: unknown".into());
                    http_util::text(200, threads)
                }
                p if p.starts_with("/debug/pprof/") => http_util::text(501, "profile not available in this build"),
                _ => http_util::text(404, "not found"),
            }
        });
        Ok(())
    })?;
    Ok(())
}
