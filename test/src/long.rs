//! `long` (the night window): waves of Services, per the standard's
//! overnight soak. Each wave creates Services, waits for every one to
//! resolve, queries them hard, deletes them, and waits for every name to go.
//!
//! What a cluster DNS holds is Services, not pods or memory, so a wave is
//! sized by ramping: each wave is larger than the last until the cluster
//! itself pushes back (a create is refused, or programming a wave takes more
//! than `SLOW`), then it varies below that ceiling. Nothing about the machine
//! is assumed or read from outside the run's namespace.
//!
//! Measured across waves: programming latency per Service, query p50/p99,
//! the latency of a fixed probe (SOA at the apex), and the residue (names
//! still resolving after the drain). A wave fails if anything it created
//! resolved wrong or was left behind. The trend fails if the probe or the
//! per-Service programming time gets more than 3x worse than in wave 1.

use crate::dns::{self, Proto};
use crate::env::Env;
use crate::kube::{Kube, Port};
use crate::report::Report;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FIRST: usize = 20;
const CEILING: usize = 2000;
/// Programming a whole wave slower than this is the cluster pushing back.
const SLOW: Duration = Duration::from_secs(120);
/// A wave's own deadlines.
const PROGRAM: Duration = Duration::from_secs(300);
/// Kept free at the end of the window, for the last drain.
const MARGIN: Duration = Duration::from_secs(900);

struct Wave {
    n: usize,
    size: usize,
    created: usize,
    program: Duration,
    unresolved: usize,
    queries: usize,
    wrong: usize,
    p50_us: u128,
    p99_us: u128,
    drain: Duration,
    residue: usize,
    probe_us: u128,
    refused: Option<String>,
}

pub async fn run(env: &Env, kube: &Kube, rep: &mut Report) -> anyhow::Result<()> {
    let start = Instant::now();
    let window = env.timeout.saturating_sub(MARGIN).max(Duration::from_secs(60));
    let server = env.server();
    let mut size = FIRST;
    let mut ceiling = CEILING;
    let mut first: Option<(u128, f64)> = None;
    let mut regressed: Option<usize> = None;
    let mut n = 0;

    while start.elapsed() < window {
        n += 1;
        let w = wave(env, kube, server, n, size).await?;
        let per_svc_ms = w.program.as_secs_f64() * 1000.0 / w.created.max(1) as f64;
        let (probe0, per0) = *first.get_or_insert((w.probe_us.max(1), per_svc_ms.max(0.001)));
        let slower = w.probe_us > probe0 * 3 + 2000 || (w.n > 1 && per_svc_ms > per0 * 3.0 + 5.0);
        if slower && regressed.is_none() {
            regressed = Some(n);
        }
        let ok = w.unresolved == 0 && w.wrong == 0 && w.residue == 0;
        let detail = format!(
            "{} services{}: programmed in {} ms ({:.1} ms each), {} queries p50 {} µs p99 {} µs, {} wrong, {} unresolved, drained in {} ms, {} left behind, probe {} µs",
            w.created,
            w.refused.as_deref().map(|r| format!(" (of {}; {r})", w.size)).unwrap_or_default(),
            w.program.as_millis(), per_svc_ms, w.queries, w.p50_us, w.p99_us, w.wrong, w.unresolved, w.drain.as_millis(), w.residue, w.probe_us
        );
        let metrics = json!({"wave": {"n": w.n, "size": w.size, "created": w.created, "program_ms": w.program.as_millis() as u64,
            "per_service_ms": per_svc_ms, "queries": w.queries, "wrong": w.wrong, "unresolved": w.unresolved, "p50_us": w.p50_us as u64,
            "p99_us": w.p99_us as u64, "drain_ms": w.drain.as_millis() as u64, "residue": w.residue, "probe_us": w.probe_us as u64}});
        rep.line(&format!("wave-{n}"), if ok { "pass" } else { "fail" }, (w.program + w.drain).as_millis(), &detail, Some(metrics));

        // Size the next wave: ramp until pushed back, then vary below it.
        if w.refused.is_some() || w.program > SLOW {
            ceiling = w.created.max(FIRST);
        }
        size = if ceiling < CEILING || size >= CEILING {
            // Past the ramp: alternate between the ceiling and a half wave.
            if n % 2 == 0 { ceiling } else { (ceiling / 2).max(FIRST) }
        } else {
            (size * 2).min(CEILING)
        };
    }

    let (status, detail) = match regressed {
        None => ("pass", format!("{n} waves, no wave more than 3x slower than wave 1 (probe or per-service programming)")),
        Some(k) => ("fail", format!("{n} waves; wave {k} was the first more than 3x slower than wave 1")),
    };
    rep.line("trend", status, start.elapsed().as_millis(), &detail, None);
    Ok(())
}

async fn wave(env: &Env, kube: &Kube, server: SocketAddr, n: usize, size: usize) -> anyhow::Result<Wave> {
    // Create, 16 at a time. A refusal ends the creating, not the wave.
    let names: Vec<String> = (0..size).map(|i| format!("w{n}-{i}")).collect();
    let mut made: Vec<(String, IpAddr)> = Vec::new();
    let mut refused = None;
    let t0 = Instant::now();
    for chunk in names.chunks(16) {
        let res = futures_join(chunk.iter().map(|s| {
            let k = kube;
            let s = s.clone();
            async move { (s.clone(), k.cluster_ip_service(&s, &[Port { name: "http", port: 80, protocol: "TCP" }]).await) }
        }))
        .await;
        for (s, r) in res {
            match r {
                Ok(ip) => made.push((s, ip)),
                Err(e) => refused = Some(format!("{e:#}")),
            }
        }
        if refused.is_some() {
            break;
        }
    }

    // Programmed: every name resolves to its ClusterIP.
    let mut pending: Vec<(String, IpAddr)> = made.iter().map(|(s, ip)| (env.svc(s), *ip)).collect();
    while !pending.is_empty() && t0.elapsed() < PROGRAM {
        let mut still = Vec::new();
        for (q, ip) in pending {
            let ok = dns::query(server, &q, RecordType::A, Proto::Udp, None, Duration::from_secs(2)).await.map(|m| dns::addrs(&m) == vec![ip]).unwrap_or(false);
            if !ok {
                still.push((q, ip));
            }
        }
        pending = still;
        if !pending.is_empty() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    let program = t0.elapsed();
    let unresolved = pending.len();

    // Exercise: 10 queries per Service, 64 in flight.
    let targets: Arc<Vec<(String, IpAddr)>> = Arc::new(made.iter().map(|(s, ip)| (env.svc(s), *ip)).collect());
    let sem = Arc::new(tokio::sync::Semaphore::new(64));
    let mut set = tokio::task::JoinSet::new();
    let queries = targets.len() * 10;
    for i in 0..queries {
        let (sem, targets) = (sem.clone(), targets.clone());
        set.spawn(async move {
            let _p = sem.acquire_owned().await;
            let (q, ip) = &targets[(i * 7919) % targets.len()];
            let t = Instant::now();
            let ok = dns::query_udp_retry(server, q, RecordType::A, Duration::from_secs(2)).await.map(|m| dns::addrs(&m) == vec![*ip]).unwrap_or(false);
            (ok, t.elapsed())
        });
    }
    let (mut wrong, mut lat) = (0, Vec::new());
    while let Some(r) = set.join_next().await {
        let (ok, d) = r?;
        if !ok {
            wrong += 1;
        }
        lat.push(d.as_micros());
    }
    lat.sort();
    let pct = |q: f64| if lat.is_empty() { 0 } else { lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)] };

    // Drain: delete everything, wait for every name to go.
    for chunk in made.chunks(16) {
        futures_join(chunk.iter().map(|(s, _)| {
            let k = kube;
            let s = s.clone();
            async move { k.delete_service(&s).await }
        }))
        .await
        .into_iter()
        .collect::<anyhow::Result<Vec<()>>>()?;
    }
    let t1 = Instant::now();
    let mut left: Vec<String> = made.iter().map(|(s, _)| env.svc(s)).collect();
    while !left.is_empty() && t1.elapsed() < PROGRAM {
        let mut still = Vec::new();
        for q in left {
            let gone = dns::query(server, &q, RecordType::A, Proto::Udp, None, Duration::from_secs(2)).await.map(|m| dns::rcode(&m) == ResponseCode::NXDomain).unwrap_or(false);
            if !gone {
                still.push(q);
            }
        }
        left = still;
        if !left.is_empty() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    Ok(Wave {
        n,
        size,
        created: made.len(),
        program,
        unresolved,
        queries,
        wrong,
        p50_us: pct(0.5),
        p99_us: pct(0.99),
        drain: t1.elapsed(),
        residue: left.len(),
        probe_us: probe(server, &env.domain).await,
        refused,
    })
}

/// Median of 50 SOA queries at the apex: the same question every wave.
async fn probe(server: SocketAddr, domain: &str) -> u128 {
    let apex = format!("{domain}.");
    let mut v = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        if dns::query(server, &apex, RecordType::SOA, Proto::Udp, None, Duration::from_secs(2)).await.is_ok() {
            v.push(t.elapsed().as_micros());
        }
    }
    v.sort();
    v.get(v.len() / 2).copied().unwrap_or(u128::MAX / 4)
}

/// Run futures concurrently and collect their outputs in order.
async fn futures_join<F, O>(it: impl Iterator<Item = F>) -> Vec<O>
where
    F: Future<Output = O>,
{
    let futs: Vec<F> = it.collect();
    let mut out = Vec::with_capacity(futs.len());
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = futs.into_iter().map(Box::pin).collect();
    // Poll them together: join_all without the futures crate.
    let mut done: Vec<Option<O>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut all = true;
        for (i, f) in pinned.iter_mut().enumerate() {
            if done[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(o) => done[i] = Some(o),
                    std::task::Poll::Pending => all = false,
                }
            }
        }
        if all { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
    })
    .await;
    for d in done {
        out.push(d.expect("every future finished"));
    }
    out
}
