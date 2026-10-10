//! `short` (< 2 min): the cluster DNS is up and does its main job, namely
//! a Service created through the API becomes a name every pod can resolve,
//! and stops being one when it is deleted.

use crate::dns::{self, Proto};
use crate::env::Env;
use crate::kube::{Kube, Port};
use crate::report::{fail, pass, Report};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::time::Duration;

/// How long a change in the API may take to show in DNS.
pub const PROGRAM: Duration = Duration::from_secs(30);

pub async fn run(env: &Env, kube: &Kube, rep: &mut Report) -> anyhow::Result<()> {
    let server = env.server();
    let apex = format!("{}.", env.domain);

    rep.check("apex-soa", async {
        let m = dns::query_udp_retry(server, &apex, RecordType::SOA, Duration::from_secs(2)).await;
        match m {
            Ok(m) if dns::rcode(&m) == ResponseCode::NoError && dns::has_type(m.answers(), RecordType::SOA) => pass(format!("{server} answers SOA for {apex}")),
            Ok(m) => fail(format!("SOA {apex} from {server}: {}", dns::show(&m))),
            Err(e) => fail(format!("{server} did not answer: {e:#}")),
        }
    })
    .await?;

    let name = "sc-short";
    let fqdn = env.svc(name);
    let ip = kube.cluster_ip_service(name, &[Port { name: "http", port: 80, protocol: "TCP" }]).await?;

    rep.check("service-a-udp", async {
        let (m, took, ok) = dns::wait_for(server, &fqdn, RecordType::A, Proto::Udp, PROGRAM, |m| dns::addrs(m) == vec![ip]).await;
        if ok {
            pass(format!("{fqdn} → {ip} after {} ms", took.as_millis()))
        } else {
            fail(format!("{fqdn} did not resolve to {ip} within {PROGRAM:?}; last: {}", m.map(|m| dns::show(&m)).unwrap_or_else(|| "no reply".into())))
        }
    })
    .await?;

    rep.check("service-a-tcp", async {
        match dns::query(server, &fqdn, RecordType::A, Proto::Tcp, None, Duration::from_secs(5)).await {
            Ok(m) if dns::addrs(&m) == vec![ip] => pass(format!("{fqdn} → {ip} over TCP")),
            Ok(m) => fail(format!("over TCP: {}", dns::show(&m))),
            Err(e) => fail(format!("over TCP: {e:#}")),
        }
    })
    .await?;

    rep.check("service-srv", async {
        let q = format!("_http._tcp.{fqdn}");
        match dns::query_udp_retry(server, &q, RecordType::SRV, Duration::from_secs(2)).await {
            Ok(m) if dns::srvs(&m) == vec![(80, fqdn.clone())] => pass(format!("{q} → 80 {fqdn}")),
            Ok(m) => fail(format!("{q}: {}", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    rep.check("nxdomain", async {
        let q = env.svc("sc-absent");
        match dns::query_udp_retry(server, &q, RecordType::A, Duration::from_secs(2)).await {
            Ok(m) if dns::rcode(&m) == ResponseCode::NXDomain && dns::has_type(m.name_servers(), RecordType::SOA) => pass(format!("{q}: NXDOMAIN with SOA")),
            Ok(m) => fail(format!("{q}: {} (want NXDOMAIN with an SOA in authority)", dns::show(&m))),
            Err(e) => fail(format!("{q}: {e:#}")),
        }
    })
    .await?;

    // A cache in front of the plugin (`cache 30` in stormcos's Corefile) may
    // keep the last answer for its TTL, as upstream CoreDNS does, so the
    // name has PROGRAM plus that TTL to go. An answer whose TTL went back up
    // after the delete was refilled from the plugin: the plugin itself still
    // has the Service.
    let ttl = match dns::query_udp_retry(server, &fqdn, RecordType::A, Duration::from_secs(2)).await {
        Ok(m) => m.answers().iter().map(|r| r.ttl()).max().unwrap_or(0),
        Err(_) => 0,
    };
    kube.delete_service(name).await?;
    rep.check("service-deleted", async {
        let within = PROGRAM + Duration::from_secs(u64::from(ttl));
        let start = std::time::Instant::now();
        let (mut last, mut prev_ttl, mut refills) = (None, u32::MAX, Vec::new());
        loop {
            if let Ok(m) = dns::query(server, &fqdn, RecordType::A, Proto::Udp, None, Duration::from_secs(2)).await {
                if dns::rcode(&m) == ResponseCode::NXDomain {
                    return pass(format!("{fqdn} NXDOMAIN {} ms after the delete (answer TTL was {ttl}s)", start.elapsed().as_millis()));
                }
                if let Some(t) = m.answers().iter().map(|r| r.ttl()).max() {
                    if t > prev_ttl {
                        refills.push(start.elapsed().as_secs());
                    }
                    prev_ttl = t;
                }
                last = Some(m);
            }
            if start.elapsed() >= within {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let why = if refills.is_empty() { "no refill seen".to_string() } else { format!("refilled from the plugin at {refills:?} s, so the plugin still has the Service") };
        fail(format!("{fqdn} still resolves {within:?} after the delete (answer TTL {ttl}s; {why}): {}", last.map(|m| dns::show(&m)).unwrap_or_else(|| "no reply".into())))
    })
    .await?;
    Ok(())
}
