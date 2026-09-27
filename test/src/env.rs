//! What the run is given, and what it finds out for itself.
//!
//! stormcentral sets the standard's `STORM_*` variables. The cluster DNS is
//! not among them, and the run's Role cannot read `kube-system`, so it comes
//! from where every pod gets it: the kubelet's `/etc/resolv.conf`, whose
//! `nameserver` is the kube-dns Service and whose first search domain is
//! `<namespace>.svc.<cluster domain>`. Nothing about the machine is assumed.

use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const SA: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

pub struct Env {
    pub api: String,
    pub run_id: String,
    pub namespace: String,
    pub timeout: Duration,
    pub commit: String,
    /// The cluster DNS server(s) pods use.
    pub dns: Vec<SocketAddr>,
    /// The cluster domain, without a trailing dot (`cluster.local`).
    pub domain: String,
    pub token: String,
    pub ca: Vec<u8>,
}

fn var(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

impl Env {
    pub fn discover(suite: &str) -> Result<Env> {
        let namespace = match var("STORM_NAMESPACE") {
            Some(n) => n,
            None => std::fs::read_to_string(format!("{SA}/namespace")).context("no STORM_NAMESPACE and no service-account namespace")?.trim().to_string(),
        };
        let api = var("STORM_API")
            .or_else(|| {
                let h = var("KUBERNETES_SERVICE_HOST")?;
                let p = var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|| "443".into());
                Some(if h.contains(':') { format!("https://[{h}]:{p}") } else { format!("https://{h}:{p}") })
            })
            .ok_or_else(|| anyhow!("no STORM_API and no KUBERNETES_SERVICE_HOST"))?;
        let token = std::fs::read_to_string(format!("{SA}/token")).context("reading the service-account token")?.trim().to_string();
        let ca = std::fs::read(format!("{SA}/ca.crt")).context("reading the service-account ca.crt")?;
        let timeout = var("STORM_TIMEOUT").and_then(|t| t.parse().ok()).map(Duration::from_secs).unwrap_or_else(|| {
            Duration::from_secs(match suite {
                "short" => 120,
                "medium" => 1800,
                _ => 8 * 3600,
            })
        });

        // Overrides for running the suites by hand against another server.
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let (servers, search) = parse_resolv(&resolv);
        let dns = match var("STORMCOREDNS_TEST_DNS") {
            Some(s) => vec![parse_server(&s)?],
            None => servers.iter().map(|ip| SocketAddr::new(*ip, 53)).collect(),
        };
        if dns.is_empty() {
            bail!("/etc/resolv.conf names no nameserver: the kubelet gave this pod no cluster DNS");
        }
        let domain = match var("STORMCOREDNS_TEST_DOMAIN") {
            Some(d) => d.trim_end_matches('.').to_string(),
            None => cluster_domain(&search, &namespace)
                .ok_or_else(|| anyhow!("no `{namespace}.svc.<domain>` in the resolv.conf search list {search:?}: not a ClusterFirst pod"))?,
        };
        Ok(Env {
            api: api.trim_end_matches('/').to_string(),
            run_id: var("STORM_RUN_ID").unwrap_or_else(|| "manual".into()),
            namespace,
            timeout,
            commit: var("STORM_COMMIT").unwrap_or_default(),
            dns,
            domain,
            token,
            ca,
        })
    }

    /// `<name>.<namespace>.svc.<domain>.`
    pub fn svc(&self, name: &str) -> String {
        format!("{name}.{}.svc.{}.", self.namespace, self.domain)
    }

    /// The cluster DNS server this run queries.
    pub fn server(&self) -> SocketAddr {
        self.dns[0]
    }

    /// A number from the run id, to spread the addresses runs put in their
    /// Endpoints (so parallel runs rarely share one).
    pub fn salt(&self) -> u8 {
        self.run_id.bytes().fold(0u8, |a, b| a.wrapping_mul(31).wrapping_add(b))
    }
}

pub fn parse_resolv(s: &str) -> (Vec<IpAddr>, Vec<String>) {
    let (mut servers, mut search) = (Vec::new(), Vec::new());
    for line in s.lines() {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("nameserver") => {
                if let Some(ip) = w.next().and_then(|a| a.parse().ok()) {
                    servers.push(ip);
                }
            }
            // The last search/domain line wins, as in the resolver.
            Some("search") | Some("domain") => search = w.map(|d| d.trim_end_matches('.').to_string()).collect(),
            _ => {}
        }
    }
    (servers, search)
}

pub fn cluster_domain(search: &[String], namespace: &str) -> Option<String> {
    let prefix = format!("{namespace}.svc.");
    search.iter().find_map(|d| d.strip_prefix(&prefix).filter(|r| !r.is_empty()).map(str::to_string))
}

fn parse_server(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    let ip: IpAddr = s.parse().with_context(|| format!("STORMCOREDNS_TEST_DNS={s}: not an address"))?;
    Ok(SocketAddr::new(ip, 53))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_kubelets_resolv_conf() {
        // As rustkube-node's kubelet writes it for a ClusterFirst pod.
        let r = "nameserver 10.96.0.10\nsearch test-x.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n";
        let (s, q) = parse_resolv(r);
        assert_eq!(s, vec!["10.96.0.10".parse::<IpAddr>().unwrap()]);
        assert_eq!(cluster_domain(&q, "test-x").as_deref(), Some("cluster.local"));
        assert_eq!(cluster_domain(&q, "other"), None);
    }

    #[test]
    fn a_node_resolv_conf_has_no_cluster_domain() {
        let (_, q) = parse_resolv("nameserver 192.168.8.252\nsearch g8.lo\n");
        assert_eq!(cluster_domain(&q, "default"), None);
    }

    #[test]
    fn server_override() {
        assert_eq!(parse_server("127.0.0.1:1053").unwrap().port(), 1053);
        assert_eq!(parse_server("::1").unwrap().port(), 53);
        assert!(parse_server("nope").is_err());
    }
}
