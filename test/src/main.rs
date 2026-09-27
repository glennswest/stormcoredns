//! stormcoredns-test: the cluster DNS of a running node, tested from a pod,
//! per stormcentral `docs/test-standard.md` (#5).
//!
//! `/test short|medium|long`. It prints one JSON object per test and a
//! summary, and exits 0 if everything passed, 1 if a test failed, and 2 if
//! the suite could not run. See test/README.md for what each suite covers
//! and what it needs.

// hickory-proto 0.24 deprecates `edns()`/`set_edns()`; the root crate allows
// the same.
#![allow(deprecated)]

mod dns;
mod env;
mod kube;
mod long;
mod medium;
mod report;
mod short;

use report::Report;

#[tokio::main]
async fn main() {
    let suite = std::env::args().nth(1).or_else(|| std::env::var("STORM_SUITE").ok()).unwrap_or_else(|| "short".into());
    std::process::exit(run(&suite).await);
}

async fn run(suite: &str) -> i32 {
    let mut rep = Report::default();
    if !matches!(suite, "short" | "medium" | "long") {
        return rep.abort(&anyhow::anyhow!("unknown suite {suite:?}: use short, medium or long"));
    }
    let env = match env::Env::discover(suite) {
        Ok(e) => e,
        Err(e) => return rep.abort(&e),
    };
    eprintln!(
        "stormcoredns-test {suite}: cluster DNS {} for {}, namespace {}, run {}, commit {}",
        env.server(),
        env.domain,
        env.namespace,
        env.run_id,
        if env.commit.is_empty() { "?" } else { &env.commit }
    );
    let kube = match kube::Kube::new(&env) {
        Ok(k) => k,
        Err(e) => return rep.abort(&e),
    };
    if let Err(e) = kube.preflight().await {
        return rep.abort(&e.context("the apiserver"));
    }
    let r = match suite {
        "short" => short::run(&env, &kube, &mut rep).await,
        "medium" => medium::run(&env, &kube, &mut rep).await,
        _ => long::run(&env, &kube, &mut rep).await,
    };
    match r {
        Ok(()) => rep.finish(),
        Err(e) => rep.abort(&e),
    }
}
