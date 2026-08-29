//! stormcoredns — CoreDNS in Rust.
//!
//! Command line matches `coredns`: `-conf`, `-dns.port`, `-pidfile`,
//! `-quiet`, `-version`, `-plugins`. Single- and double-dash forms both work.

pub mod corefile;
pub mod dnsutil;
pub mod metrics;
pub mod plugin;
pub mod plugins;
pub mod server;

use anyhow::{bail, Context, Result};
use server::build::BuildOptions;
use server::Instance;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The CoreDNS release whose plugin set and behaviour this build tracks.
pub const COREDNS_COMPAT: &str = "1.12";

struct Args {
    conf: PathBuf,
    port: u16,
    pidfile: Option<PathBuf>,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage of stormcoredns:
  -conf string
        Corefile to load (default \"Corefile\")
  -dns.port string
        Default port (default \"53\")
  -pidfile string
        Path to write pid file
  -plugins
        List installed plugins
  -quiet
        Quiet mode (no initialization output)
  -version
        Show version"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args { conf: PathBuf::from("Corefile"), port: 53, pidfile: None, quiet: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let flag = arg.trim_start_matches('-');
        let (name, inline_val) = match flag.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (flag.to_string(), None),
        };
        let mut value = |it: &mut std::iter::Skip<std::env::Args>| -> String {
            inline_val.clone().or_else(|| it.next()).unwrap_or_else(|| usage())
        };
        match name.as_str() {
            "conf" => a.conf = PathBuf::from(value(&mut it)),
            "dns.port" | "p" => {
                a.port = value(&mut it).parse().unwrap_or_else(|_| usage());
            }
            "pidfile" => a.pidfile = Some(PathBuf::from(value(&mut it))),
            "quiet" | "q" => a.quiet = true,
            "version" | "v" => {
                println!("stormcoredns-{} (CoreDNS-{} compatible)", VERSION, COREDNS_COMPAT);
                std::process::exit(0);
            }
            "plugins" => {
                println!("Server types:\n  dns\n\nCaddyfile loaders:\n  flag\n  default\n\nOther plugins:");
                for n in plugin::registry::names() {
                    println!("  dns.{}", n);
                }
                std::process::exit(0);
            }
            "h" | "help" => usage(),
            // accepted for compatibility with glog flags
            "alsologtostderr" | "logtostderr" | "log_dir" | "stderrthreshold" | "v_module" | "vmodule" | "log_backtrace_at" => {
                if inline_val.is_none() && !matches!(name.as_str(), "alsologtostderr" | "logtostderr") {
                    let _ = it.next();
                }
            }
            _ => {
                eprintln!("flag provided but not defined: -{}", name);
                usage();
            }
        }
    }
    if let Ok(p) = std::env::var("PORT") {
        if let Ok(p) = p.parse() {
            a.port = p;
        }
    }
    a
}

fn init_logging(quiet: bool) {
    let filter = EnvFilter::try_from_env("STORMCOREDNS_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new(if quiet { "warn" } else { "info" }));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();
}

fn main() -> Result<()> {
    let args = parse_args();
    init_logging(args.quiet);
    server::tls::init_crypto();
    metrics::init_build_info();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(run(args))
}

async fn load(args: &Args) -> Result<Instance> {
    let blocks = corefile::parse_file(&args.conf)?;
    if blocks.is_empty() {
        bail!("{}: no server blocks", args.conf.display());
    }
    let opts = BuildOptions { default_port: args.port, corefile: args.conf.clone(), quiet: args.quiet };
    Instance::start(blocks, &opts).await
}

async fn run(args: Args) -> Result<()> {
    if let Some(p) = &args.pidfile {
        std::fs::write(p, format!("{}\n", std::process::id())).with_context(|| format!("writing pidfile {}", p.display()))?;
    }
    let mut inst = load(&args).await.map_err(|e| {
        eprintln!("{}", e);
        e
    })?;
    if !args.quiet {
        for c in &inst.configs {
            println!("{}:{}", c.zone, c.port);
        }
        println!("stormcoredns-{} (CoreDNS-{} compatible)", VERSION, COREDNS_COMPAT);
        println!("{}/{}, rust", std::env::consts::OS, std::env::consts::ARCH);
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { tracing::info!("SIGINT: shutting down"); break; }
            _ = sigterm.recv() => { tracing::info!("SIGTERM: shutting down"); break; }
            _ = sigusr1.recv() => {
                tracing::info!("SIGUSR1: reloading");
                inst = reload(&args, inst).await;
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP: reloading");
                inst = reload(&args, inst).await;
            }
            _ = Instance::wait_reload() => {
                tracing::info!("Reloading");
                inst = reload(&args, inst).await;
            }
        }
    }
    inst.stop().await;
    if let Some(p) = &args.pidfile {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Start a new instance from the Corefile; on failure keep the old one
/// (running its `restart_failed` hooks).
async fn reload(args: &Args, old: Instance) -> Instance {
    match load(args).await {
        Ok(new) => {
            old.stop().await;
            tracing::info!("Reloading complete");
            new
        }
        Err(e) => {
            tracing::error!("Restart failed: {}", e);
            metrics::RELOAD_FAILED.inc();
            let mut old = old;
            for h in old.restart_failed_hooks.drain(..) {
                if let Err(e) = h().await {
                    tracing::warn!("restart_failed hook: {}", e);
                }
            }
            old
        }
    }
}
