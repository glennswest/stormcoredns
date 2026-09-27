//! `medium` (< 30 min): the kubernetes plugin's record set end to end, and
//! the server's failure paths: truncation, malformed queries, a changing
//! and a vanishing backend, load.

use crate::dns::{self, Proto};
use crate::env::Env;
use crate::kube::{Addr, Kube, Port};
use crate::report::{fail, pass, Outcome, Report};
use crate::short::PROGRAM;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(3);

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn last(m: Option<hickory_proto::op::Message>) -> String {
    m.map(|m| dns::show(&m)).unwrap_or_else(|| "no reply".into())
}

pub async fn run(env: &Env, kube: &Kube, rep: &mut Report) -> anyhow::Result<()> {
    let server = env.server();
    let salt = env.salt();
    let db = || vec![Port { name: "db", port: 5432, protocol: "TCP" }];
    // Addresses from the benchmarking range (RFC 2544), spread by the run id.
    let backends: Vec<Addr> = (0..3).map(|i| Addr { ip: ip(198, 18, salt, 10 + i), hostname: Some(format!("ep-{i}")) }).collect();
    let want: Vec<IpAddr> = backends.iter().map(|a| a.ip).collect();

    // ── a ClusterIP service ───────────────────────────────────────────────
    let web = env.svc("sc-web");
    let web_ip = kube.cluster_ip_service("sc-web", &[Port { name: "http", port: 80, protocol: "TCP" }, Port { name: "dns", port: 53, protocol: "UDP" }]).await?;
    rep.check("clusterip-a", async {
        let (m, took, ok) = dns::wait_for(server, &web, RecordType::A, Proto::Udp, PROGRAM, |m| dns::addrs(m) == vec![web_ip]).await;
        if ok { pass(format!("{web} → {web_ip} after {} ms", took.as_millis())) } else { fail(format!("{web}: {}", last(m))) }
    })
    .await?;

    rep.check("clusterip-srv-udp-port", async {
        let q = format!("_dns._udp.{web}");
        match dns::query_udp_retry(server, &q, RecordType::SRV, T).await {
            Ok(m) if dns::srvs(&m) == vec![(53, web.clone())] => pass(format!("{q} → 53 {web}")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("clusterip-ptr", async {
        let q = dns::reverse(web_ip);
        match dns::query_udp_retry(server, &q, RecordType::PTR, T).await {
            Ok(m) if dns::ptrs(&m).contains(&web) => pass(format!("{q} → {web}")),
            Ok(m) => fail(format!("{q}: {} (want {web})", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("case-insensitive", async {
        let q = web.to_uppercase();
        match dns::query_udp_retry(server, &q, RecordType::A, T).await {
            Ok(m) if dns::addrs(&m) == vec![web_ip] => pass(format!("{q} → {web_ip}")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("nodata", async {
        // The name exists, the type does not: NOERROR, no answers, an SOA.
        match dns::query_udp_retry(server, &web, RecordType::MX, T).await {
            Ok(m) if dns::rcode(&m) == ResponseCode::NoError && m.answers().is_empty() && dns::has_type(m.name_servers(), RecordType::SOA) => pass(format!("{web} MX: NODATA with SOA")),
            Ok(m) => fail(format!("{web} MX: {} (want NOERROR, no answer, SOA)", dns::show(&m))),
            Err(e) => fail(format!("{web} MX: {e:#}")),
        }
    })
    .await?;

    // ── a headless service with named endpoints ───────────────────────────
    let hl = env.svc("sc-hl");
    kube.headless_service("sc-hl", &db(), &backends).await?;
    rep.check("headless-a", async {
        let (m, took, ok) = dns::wait_for(server, &hl, RecordType::A, Proto::Udp, PROGRAM, |m| dns::addrs(m) == want).await;
        if ok { pass(format!("{hl} → {want:?} after {} ms", took.as_millis())) } else { fail(format!("{hl}: {} (want {want:?})", last(m))) }
    })
    .await?;

    rep.check("endpoint-hostname", async {
        let q = format!("ep-1.{hl}");
        match dns::query_udp_retry(server, &q, RecordType::A, T).await {
            Ok(m) if dns::addrs(&m) == vec![want[1]] => pass(format!("{q} → {}", want[1])),
            Ok(m) => fail(format!("{q}: {} (want {})", dns::show(&m), want[1])),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("headless-srv", async {
        let q = format!("_db._tcp.{hl}");
        let mut expect: Vec<(u16, String)> = (0..3).map(|i| (5432, format!("ep-{i}.{hl}"))).collect();
        expect.sort();
        match dns::query_udp_retry(server, &q, RecordType::SRV, T).await {
            Ok(m) if dns::srvs(&m) == expect => pass(format!("{q} → 3 targets ep-N.{hl}")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("endpoint-ptr", async {
        let q = dns::reverse(want[0]);
        let expect = format!("ep-0.{hl}");
        match dns::query_udp_retry(server, &q, RecordType::PTR, T).await {
            Ok(m) if dns::ptrs(&m).contains(&expect) => pass(format!("{q} → {expect}")),
            Ok(m) => fail(format!("{q}: {} (want {expect})", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("endpoints-change", async {
        let moved: Vec<Addr> = (0..2).map(|i| Addr { ip: ip(198, 18, salt, 50 + i), hostname: None }).collect();
        let now: Vec<IpAddr> = moved.iter().map(|a| a.ip).collect();
        kube.set_endpoints("sc-hl", &db(), &moved).await?;
        let (m, took, ok) = dns::wait_for(server, &hl, RecordType::A, Proto::Udp, PROGRAM, |m| dns::addrs(m) == now).await;
        if ok { pass(format!("{hl} followed the new backends {now:?} in {} ms", took.as_millis())) } else { fail(format!("{hl}: {} (want {now:?})", last(m))) }
    })
    .await?;

    rep.check("dashed-ip-endpoint", async {
        // An endpoint without a hostname is named by its dashed address.
        let q = format!("198-18-{salt}-50.{hl}");
        match dns::query_udp_retry(server, &q, RecordType::A, T).await {
            Ok(m) if dns::addrs(&m) == vec![ip(198, 18, salt, 50)] => pass(format!("{q} → 198.18.{salt}.50")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    // ── ExternalName, pods, apex ──────────────────────────────────────────
    rep.check("externalname-cname", async {
        let ext = env.svc("sc-ext");
        let target = format!("elsewhere.{}.invalid.", env.run_id.to_lowercase().replace(|c: char| !c.is_ascii_alphanumeric(), "-"));
        kube.external_name_service("sc-ext", target.trim_end_matches('.')).await?;
        let (m, took, ok) = dns::wait_for(server, &ext, RecordType::CNAME, Proto::Udp, PROGRAM, |m| dns::cnames(m).contains(&target)).await;
        if ok { pass(format!("{ext} CNAME {target} after {} ms", took.as_millis())) } else { fail(format!("{ext}: {} (want CNAME {target})", last(m))) }
    })
    .await?;

    rep.check("pod-by-address", async {
        let q = format!("198-18-{salt}-7.{}.pod.{}.", env.namespace, env.domain);
        match dns::query_udp_retry(server, &q, RecordType::A, T).await {
            Ok(m) if dns::addrs(&m) == vec![ip(198, 18, salt, 7)] => pass(format!("{q} → 198.18.{salt}.7")),
            Ok(m) => fail(format!("{q}: {} (the stormcos Corefile has `pods insecure`)", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("dns-version", async {
        let q = format!("dns-version.{}.", env.domain);
        match dns::query_udp_retry(server, &q, RecordType::TXT, T).await {
            Ok(m) if dns::txts(&m) == vec!["1.1.0".to_string()] => pass(format!("{q} TXT 1.1.0")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("apex-ns", async {
        let q = format!("{}.", env.domain);
        match dns::query_udp_retry(server, &q, RecordType::NS, T).await {
            Ok(m) if dns::has_type(m.answers(), RecordType::NS) => pass(format!("{q} NS: {}", dns::show(&m))),
            Ok(m) => fail(format!("{q} NS: {}", dns::show(&m))),
            Err(e) => fail(format!("{q} NS: {e:#}")),
        }
    })
    .await?;

    // ── size: truncation over UDP, whole over TCP and with EDNS ────────────
    let big = env.svc("sc-big");
    let many: Vec<Addr> = (1..=100).map(|i| Addr { ip: ip(198, 19, salt, i), hostname: None }).collect();
    let all: Vec<IpAddr> = many.iter().map(|a| a.ip).collect();
    kube.headless_service("sc-big", &db(), &many).await?;
    let (_, _, programmed) = dns::wait_for(server, &big, RecordType::A, Proto::Tcp, PROGRAM, |m| dns::addrs(m).len() == 100).await;

    rep.check("udp-truncates", async {
        if !programmed {
            return fail(format!("{big} never showed its 100 endpoints over TCP"));
        }
        match dns::query(server, &big, RecordType::A, Proto::Udp, None, T).await {
            Ok(m) if m.truncated() => pass(format!("{big} over UDP without EDNS: TC with {} of 100 answers", m.answers().len())),
            Ok(m) => fail(format!("{big} over UDP without EDNS: {} answers and no TC (512-byte limit)", m.answers().len())),
            Err(e) => fail(format!("{big}: {e:#}")),
        }
    })
    .await?;

    rep.check("tcp-whole", async {
        match dns::query(server, &big, RecordType::A, Proto::Tcp, None, T).await {
            Ok(m) if dns::addrs(&m) == all && !m.truncated() => pass(format!("{big} over TCP: all 100")),
            Ok(m) => fail(format!("{big} over TCP: {} answers, TC={}", m.answers().len(), m.truncated())),
            Err(e) => fail(format!("{big} over TCP: {e:#}")),
        }
    })
    .await?;

    rep.check("edns-whole", async {
        match dns::query(server, &big, RecordType::A, Proto::Udp, Some(4096), T).await {
            Ok(m) if dns::addrs(&m) == all && !m.truncated() => pass(format!("{big} over UDP with EDNS 4096: all 100")),
            Ok(m) => fail(format!("{big} with EDNS 4096: {} answers, TC={}", m.answers().len(), m.truncated())),
            Err(e) => fail(format!("{big} with EDNS 4096: {e:#}")),
        }
    })
    .await?;

    // ── failure paths ─────────────────────────────────────────────────────
    rep.check("formerr", async {
        // A header that promises a question and carries none.
        let id: u16 = 0x5c0d;
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        match dns::exchange_udp(server, &wire, id, T).await {
            Ok(r) if r.len() >= 4 && r[3] & 0x0f == 1 => pass("a question-less query gets FORMERR with its id"),
            Ok(r) => fail(format!("a malformed query got rcode {} (want FORMERR)", r.get(3).map(|b| b & 0x0f).unwrap_or(255))),
            Err(e) => fail(format!("no reply to a malformed query: {e:#}")),
        }
    })
    .await?;

    rep.check("forward-answers", async {
        // Outside the cluster zone: `forward` must answer (any rcode but
        // SERVFAIL), not hang. `.invalid` never exists (RFC 6761).
        let q = format!("sc-{}.invalid.", salt);
        match dns::query_udp_retry(server, &q, RecordType::A, Duration::from_secs(5)).await {
            Ok(m) if dns::rcode(&m) != ResponseCode::ServFail => pass(format!("{q}: {:?} from the upstream", dns::rcode(&m))),
            Ok(m) => fail(format!("{q}: {} (forward failed)", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("load", async { load(server, &web, web_ip).await }).await?;

    // ── deletion ──────────────────────────────────────────────────────────
    for s in ["sc-web", "sc-hl", "sc-big", "sc-ext"] {
        kube.delete_service(s).await?;
    }
    rep.check("deleted-services-vanish", async {
        let start = Instant::now();
        let mut left = Vec::new();
        for s in ["sc-web", "sc-hl", "sc-big", "sc-ext"] {
            let q = env.svc(s);
            let rest = PROGRAM.saturating_sub(start.elapsed());
            let (_, _, ok) = dns::wait_for(server, &q, RecordType::A, Proto::Udp, rest, |m| dns::rcode(m) == ResponseCode::NXDomain).await;
            if !ok {
                left.push(q);
            }
        }
        if left.is_empty() { pass(format!("all four NXDOMAIN within {} ms", start.elapsed().as_millis())) } else { fail(format!("still resolving {PROGRAM:?} after delete: {left:?}")) }
    })
    .await?;
    Ok(())
}

/// 2000 queries, 50 at a time, all correct, and the latency spread.
async fn load(server: std::net::SocketAddr, name: &str, want: IpAddr) -> anyhow::Result<Outcome> {
    let sem = Arc::new(tokio::sync::Semaphore::new(50));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..2000 {
        let (sem, name) = (sem.clone(), name.to_string());
        set.spawn(async move {
            let _p = sem.acquire_owned().await;
            let t = Instant::now();
            let r = dns::query_udp_retry(server, &name, RecordType::A, T).await;
            (r.map(|m| dns::addrs(&m) == vec![want]).unwrap_or(false), t.elapsed())
        });
    }
    let (mut bad, mut lat) = (0, Vec::new());
    while let Some(r) = set.join_next().await {
        let (ok, d) = r?;
        if !ok {
            bad += 1;
        }
        lat.push(d);
    }
    lat.sort();
    let p = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)].as_micros();
    let detail = format!("2000 queries, 50 concurrent: {bad} wrong or lost, p50 {} µs, p99 {} µs", p(0.5), p(0.99));
    if bad == 0 { pass(detail) } else { fail(detail) }
}
