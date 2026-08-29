//! In-memory index of the Kubernetes objects the DNS schema needs, kept
//! current by watchers on Services, EndpointSlices (or core Endpoints),
//! Pods and Namespaces.

use anyhow::Result;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::{Endpoints, Namespace, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::watcher::{self, Event};
use kube::runtime::WatchStreamExt;
use kube::{Api, Client, ResourceExt};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    /// "TCP", "UDP", "SCTP" (upper case as in the API).
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub pod_name: Option<String>,
    pub ready: bool,
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone)]
pub struct Svc {
    pub name: String,
    pub namespace: String,
    pub cluster_ips: Vec<IpAddr>,
    pub headless: bool,
    pub external_name: Option<String>,
    pub ports: Vec<Port>,
    pub publish_not_ready: bool,
}

impl Svc {
    pub fn key(&self) -> (String, String) {
        (self.namespace.clone(), self.name.clone())
    }
}

#[derive(Debug, Clone)]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub ips: Vec<IpAddr>,
}

type Key = (String, String); // (namespace, name)

#[derive(Default)]
pub struct Store {
    services: RwLock<HashMap<Key, Arc<Svc>>>,
    svc_by_ip: RwLock<HashMap<IpAddr, Key>>,
    /// (ns, service) → slice name → endpoints
    endpoints: RwLock<HashMap<Key, HashMap<String, Vec<Endpoint>>>>,
    ep_by_ip: RwLock<HashMap<IpAddr, HashSet<Key>>>,
    pods: RwLock<HashMap<Key, Arc<PodInfo>>>,
    pod_by_ip: RwLock<HashMap<IpAddr, Key>>,
    namespaces: RwLock<HashSet<String>>,
    pub services_synced: AtomicBool,
    pub endpoints_synced: AtomicBool,
    pub pods_synced: AtomicBool,
    pub namespaces_synced: AtomicBool,
}

/// `coredns_kubernetes_dns_programming_duration_seconds`.
static PROGRAMMING_LATENCY: once_cell::sync::Lazy<prometheus::HistogramVec> = once_cell::sync::Lazy::new(|| {
    let h = prometheus::HistogramVec::new(
        prometheus::HistogramOpts::new(
            "coredns_kubernetes_dns_programming_duration_seconds",
            "Histogram of the time (in seconds) it took to program a dns instance.",
        )
        .buckets(vec![0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256, 0.512, 1.024, 2.048, 4.096, 8.192, 16.384, 32.768, 65.536, 131.072, 262.144, 524.288]),
        &["service_kind"],
    )
    .unwrap();
    crate::metrics::register(Box::new(h.clone()));
    h
});

impl Store {
    pub fn new() -> Arc<Store> {
        once_cell::sync::Lazy::force(&PROGRAMMING_LATENCY);
        Arc::new(Store::default())
    }

    // ------------------------------------------------------------ queries

    pub fn service(&self, ns: &str, name: &str) -> Option<Arc<Svc>> {
        self.services.read().get(&(ns.to_string(), name.to_string())).cloned()
    }

    /// Services in a namespace ("*" for all namespaces).
    pub fn services_in(&self, ns: &str) -> Vec<Arc<Svc>> {
        self.services.read().values().filter(|s| ns == "*" || s.namespace == ns).cloned().collect()
    }

    pub fn service_by_ip(&self, ip: IpAddr) -> Option<Arc<Svc>> {
        let k = self.svc_by_ip.read().get(&ip).cloned()?;
        self.services.read().get(&k).cloned()
    }

    /// All endpoints of a service, slices merged.
    pub fn endpoints(&self, ns: &str, name: &str) -> Vec<Endpoint> {
        self.endpoints
            .read()
            .get(&(ns.to_string(), name.to_string()))
            .map(|slices| slices.values().flatten().cloned().collect())
            .unwrap_or_default()
    }

    /// Services (keys) that have an endpoint with this IP.
    pub fn services_by_endpoint_ip(&self, ip: IpAddr) -> Vec<Key> {
        self.ep_by_ip.read().get(&ip).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    pub fn pod_by_ip(&self, ip: IpAddr) -> Option<Arc<PodInfo>> {
        let k = self.pod_by_ip.read().get(&ip).cloned()?;
        self.pods.read().get(&k).cloned()
    }

    pub fn namespace_exists(&self, ns: &str) -> bool {
        self.namespaces.read().contains(ns)
    }

    pub fn namespaces(&self) -> Vec<String> {
        self.namespaces.read().iter().cloned().collect()
    }

    pub fn synced(&self, pods: bool, endpoints: bool) -> bool {
        self.services_synced.load(Ordering::Relaxed)
            && self.namespaces_synced.load(Ordering::Relaxed)
            && (!endpoints || self.endpoints_synced.load(Ordering::Relaxed))
            && (!pods || self.pods_synced.load(Ordering::Relaxed))
    }

    // ------------------------------------------------------------ mutation

    fn apply_service(&self, s: &Service) {
        let Some(svc) = convert_service(s) else { return };
        let key = svc.key();
        let mut by_ip = self.svc_by_ip.write();
        let mut services = self.services.write();
        if let Some(old) = services.get(&key) {
            for ip in &old.cluster_ips {
                by_ip.remove(ip);
            }
        }
        for ip in &svc.cluster_ips {
            by_ip.insert(*ip, key.clone());
        }
        services.insert(key, Arc::new(svc));
    }

    fn delete_service(&self, s: &Service) {
        let key = (s.namespace().unwrap_or_default(), s.name_any());
        let mut by_ip = self.svc_by_ip.write();
        if let Some(old) = self.services.write().remove(&key) {
            for ip in &old.cluster_ips {
                by_ip.remove(ip);
            }
        }
    }

    fn set_slice(&self, svc_key: Key, slice: String, eps: Vec<Endpoint>) {
        let mut all = self.endpoints.write();
        let mut by_ip = self.ep_by_ip.write();
        let slices = all.entry(svc_key.clone()).or_default();
        if let Some(old) = slices.remove(&slice) {
            for e in old {
                for ip in e.ips {
                    if let Some(set) = by_ip.get_mut(&ip) {
                        set.remove(&svc_key);
                        if set.is_empty() {
                            by_ip.remove(&ip);
                        }
                    }
                }
            }
        }
        for e in &eps {
            for ip in &e.ips {
                by_ip.entry(*ip).or_default().insert(svc_key.clone());
            }
        }
        if eps.is_empty() {
            if slices.is_empty() {
                all.remove(&svc_key);
            }
        } else {
            slices.insert(slice, eps);
        }
    }

    fn apply_slice(&self, s: &EndpointSlice) {
        let Some(svc_name) = s.labels().get("kubernetes.io/service-name").cloned() else { return };
        let ns = s.namespace().unwrap_or_default();
        let slice = s.name_any();
        let ports: Vec<Port> = s
            .ports
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .filter_map(|p| {
                        Some(Port {
                            name: p.name.clone().unwrap_or_default(),
                            protocol: p.protocol.clone().unwrap_or_else(|| "TCP".into()),
                            port: u16::try_from(p.port?).ok()?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let eps: Vec<Endpoint> = s
            .endpoints
            .iter()
            .map(|e| Endpoint {
                ips: e.addresses.iter().filter_map(|a| a.parse().ok()).collect(),
                hostname: e.hostname.clone(),
                pod_name: e.target_ref.as_ref().filter(|r| r.kind.as_deref() == Some("Pod")).and_then(|r| r.name.clone()),
                ready: e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true),
                ports: ports.clone(),
            })
            .collect();
        self.observe_programming(&s.annotations(), "headless_with_selector");
        self.set_slice((ns, svc_name), slice, eps);
    }

    fn delete_slice(&self, s: &EndpointSlice) {
        let Some(svc_name) = s.labels().get("kubernetes.io/service-name").cloned() else { return };
        let ns = s.namespace().unwrap_or_default();
        self.set_slice((ns, svc_name), s.name_any(), Vec::new());
    }

    fn apply_endpoints(&self, e: &Endpoints) {
        let ns = e.namespace().unwrap_or_default();
        let name = e.name_any();
        let mut eps = Vec::new();
        for subset in e.subsets.as_deref().unwrap_or(&[]) {
            let ports: Vec<Port> = subset
                .ports
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|p| {
                    Some(Port { name: p.name.clone().unwrap_or_default(), protocol: p.protocol.clone().unwrap_or_else(|| "TCP".into()), port: u16::try_from(p.port).ok()? })
                })
                .collect();
            for (addrs, ready) in [(subset.addresses.as_deref(), true), (subset.not_ready_addresses.as_deref(), false)] {
                for a in addrs.unwrap_or(&[]) {
                    eps.push(Endpoint {
                        ips: a.ip.parse().ok().into_iter().collect(),
                        hostname: a.hostname.clone(),
                        pod_name: a.target_ref.as_ref().filter(|r| r.kind.as_deref() == Some("Pod")).and_then(|r| r.name.clone()),
                        ready,
                        ports: ports.clone(),
                    });
                }
            }
        }
        self.observe_programming(&e.annotations(), "headless_with_selector");
        self.set_slice((ns, name), "endpoints".into(), eps);
    }

    fn delete_endpoints(&self, e: &Endpoints) {
        self.set_slice((e.namespace().unwrap_or_default(), e.name_any()), "endpoints".into(), Vec::new());
    }

    fn observe_programming(&self, annotations: &std::collections::BTreeMap<String, String>, kind: &str) {
        if let Some(t) = annotations.get("endpoints.kubernetes.io/last-change-trigger-time") {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(t) {
                let lag = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
                if let Ok(d) = lag.to_std() {
                    PROGRAMMING_LATENCY.with_label_values(&[kind]).observe(d.as_secs_f64());
                }
            }
        }
    }

    fn apply_pod(&self, p: &Pod) {
        let key = (p.namespace().unwrap_or_default(), p.name_any());
        let phase = p.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
        let mut ips: Vec<IpAddr> = p
            .status
            .as_ref()
            .and_then(|s| s.pod_ips.as_ref())
            .map(|v| v.iter().filter_map(|i| i.ip.parse().ok()).collect())
            .unwrap_or_default();
        if ips.is_empty() {
            if let Some(ip) = p.status.as_ref().and_then(|s| s.pod_ip.as_ref()).and_then(|s| s.parse().ok()) {
                ips.push(ip);
            }
        }
        let mut by_ip = self.pod_by_ip.write();
        let mut pods = self.pods.write();
        if let Some(old) = pods.remove(&key) {
            for ip in &old.ips {
                by_ip.remove(ip);
            }
        }
        if ips.is_empty() || phase == "Succeeded" || phase == "Failed" {
            return;
        }
        for ip in &ips {
            by_ip.insert(*ip, key.clone());
        }
        pods.insert(key.clone(), Arc::new(PodInfo { name: key.1.clone(), namespace: key.0.clone(), ips }));
    }

    fn delete_pod(&self, p: &Pod) {
        let key = (p.namespace().unwrap_or_default(), p.name_any());
        let mut by_ip = self.pod_by_ip.write();
        if let Some(old) = self.pods.write().remove(&key) {
            for ip in &old.ips {
                by_ip.remove(ip);
            }
        }
    }

    fn apply_namespace(&self, n: &Namespace) {
        self.namespaces.write().insert(n.name_any());
    }
    fn delete_namespace(&self, n: &Namespace) {
        self.namespaces.write().remove(&n.name_any());
    }
}

fn convert_service(s: &Service) -> Option<Svc> {
    let name = s.name_any();
    let namespace = s.namespace()?;
    let spec = s.spec.as_ref()?;
    let ty = spec.type_.clone().unwrap_or_else(|| "ClusterIP".into());
    let mut cluster_ips: Vec<IpAddr> = spec.cluster_ips.as_deref().unwrap_or(&[]).iter().filter_map(|s| s.parse().ok()).collect();
    if cluster_ips.is_empty() {
        if let Some(ip) = spec.cluster_ip.as_ref().and_then(|s| s.parse().ok()) {
            cluster_ips.push(ip);
        }
    }
    let headless = spec.cluster_ip.as_deref() == Some("None") || (cluster_ips.is_empty() && ty != "ExternalName");
    let ports = spec
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|p| Some(Port { name: p.name.clone().unwrap_or_default(), protocol: p.protocol.clone().unwrap_or_else(|| "TCP".into()), port: u16::try_from(p.port).ok()? }))
        .collect();
    Some(Svc {
        name,
        namespace,
        cluster_ips,
        headless,
        external_name: if ty == "ExternalName" { spec.external_name.clone() } else { None },
        ports,
        publish_not_ready: spec.publish_not_ready_addresses.unwrap_or(false),
    })
}

// ------------------------------------------------------------------ watches

/// Generic watch loop: keeps `store` in sync with one resource kind.
async fn watch_loop<K>(
    api: Api<K>,
    cfg: watcher::Config,
    store: Arc<Store>,
    apply: fn(&Store, &K),
    delete: fn(&Store, &K),
    retain: fn(&Store, &HashSet<Key>),
    synced: fn(&Store) -> &AtomicBool,
    what: &'static str,
) where
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned + Send + 'static,
    K::DynamicType: Default,
{
    let mut stream = std::pin::pin!(watcher::watcher(api, cfg).default_backoff());
    let mut seen: HashSet<Key> = HashSet::new();
    loop {
        match stream.try_next().await {
            Ok(Some(ev)) => match ev {
                Event::Init => seen.clear(),
                Event::InitApply(o) => {
                    seen.insert(key_of(&o));
                    apply(&store, &o);
                }
                Event::InitDone => {
                    // drop objects that disappeared while we were not watching
                    retain(&store, &seen);
                    if !synced(&store).swap(true, Ordering::Relaxed) {
                        tracing::info!("plugin/kubernetes: {} synced", what);
                    }
                }
                Event::Apply(o) => apply(&store, &o),
                Event::Delete(o) => delete(&store, &o),
            },
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("plugin/kubernetes: {} watch: {}", what, e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

fn key_of<K: kube::Resource>(o: &K) -> Key {
    (o.meta().namespace.clone().unwrap_or_default(), o.meta().name.clone().unwrap_or_default())
}

impl Store {
    fn retain_services(&self, seen: &HashSet<Key>) {
        let gone: Vec<Key> = self.services.read().keys().filter(|k| !seen.contains(*k)).cloned().collect();
        let mut by_ip = self.svc_by_ip.write();
        let mut services = self.services.write();
        for k in gone {
            if let Some(old) = services.remove(&k) {
                for ip in &old.cluster_ips {
                    by_ip.remove(ip);
                }
            }
        }
    }
    /// `seen` holds (namespace, slice name) pairs.
    fn retain_slices(&self, seen: &HashSet<Key>) {
        let gone: Vec<(Key, String)> = self
            .endpoints
            .read()
            .iter()
            .flat_map(|(svc, slices)| slices.keys().map(move |sl| (svc.clone(), sl.clone())))
            .filter(|(svc, sl)| !seen.contains(&(svc.0.clone(), sl.clone())))
            .collect();
        for (svc, sl) in gone {
            self.set_slice(svc, sl, Vec::new());
        }
    }
    /// core Endpoints: one pseudo-slice "endpoints" per (namespace, name).
    fn retain_endpoints(&self, seen: &HashSet<Key>) {
        let gone: Vec<Key> = self.endpoints.read().keys().filter(|k| !seen.contains(*k)).cloned().collect();
        for k in gone {
            self.set_slice(k, "endpoints".into(), Vec::new());
        }
    }
    fn retain_pods(&self, seen: &HashSet<Key>) {
        let gone: Vec<Key> = self.pods.read().keys().filter(|k| !seen.contains(*k)).cloned().collect();
        let mut by_ip = self.pod_by_ip.write();
        let mut pods = self.pods.write();
        for k in gone {
            if let Some(old) = pods.remove(&k) {
                for ip in &old.ips {
                    by_ip.remove(ip);
                }
            }
        }
    }
    fn retain_namespaces(&self, seen: &HashSet<Key>) {
        self.namespaces.write().retain(|n| seen.contains(&(String::new(), n.clone())));
    }
}

#[derive(Debug, Clone, Default)]
pub struct WatchOptions {
    pub namespaces: Vec<String>,
    pub label_selector: Option<String>,
    pub namespace_label_selector: Option<String>,
    pub watch_pods: bool,
    pub watch_endpoints: bool,
}

/// Start all watchers. Uses EndpointSlices when the discovery API exists,
/// core Endpoints otherwise (older clusters, minimal API servers).
pub async fn start(client: Client, store: Arc<Store>, opts: WatchOptions) -> Result<()> {
    let mut cfg = watcher::Config::default();
    if let Some(l) = &opts.label_selector {
        cfg = cfg.labels(l);
    }
    // services
    {
        let (store, cfg) = (store.clone(), cfg.clone());
        let api: Api<Service> = Api::all(client.clone());
        tokio::spawn(watch_loop(
            api,
            cfg,
            store,
            |s, o| s.apply_service(o),
            |s, o| s.delete_service(o),
            |s, seen| s.retain_services(seen),
            |s| &s.services_synced,
            "services",
        ));
    }
    // namespaces
    {
        let store = store.clone();
        let mut ncfg = watcher::Config::default();
        if let Some(l) = &opts.namespace_label_selector {
            ncfg = ncfg.labels(l);
        }
        let api: Api<Namespace> = Api::all(client.clone());
        tokio::spawn(watch_loop(
            api,
            ncfg,
            store,
            |s, o| s.apply_namespace(o),
            |s, o| s.delete_namespace(o),
            |s, seen| s.retain_namespaces(seen),
            |s| &s.namespaces_synced,
            "namespaces",
        ));
    }
    // endpoints
    if opts.watch_endpoints {
        let have_slices = client.list_api_group_resources("discovery.k8s.io/v1").await.map(|l| l.resources.iter().any(|r| r.name == "endpointslices")).unwrap_or(false);
        if have_slices {
            let (store, cfg) = (store.clone(), cfg.clone());
            let api: Api<EndpointSlice> = Api::all(client.clone());
            tokio::spawn(watch_loop(
                api,
                cfg,
                store,
                |s, o| s.apply_slice(o),
                |s, o| s.delete_slice(o),
                |s, seen| s.retain_slices(seen),
                |s| &s.endpoints_synced,
                "endpointslices",
            ));
        } else {
            tracing::info!("plugin/kubernetes: discovery.k8s.io/v1 not available, watching core Endpoints");
            let (store, cfg) = (store.clone(), cfg.clone());
            let api: Api<Endpoints> = Api::all(client.clone());
            tokio::spawn(watch_loop(
                api,
                cfg,
                store,
                |s, o| s.apply_endpoints(o),
                |s, o| s.delete_endpoints(o),
                |s, seen| s.retain_endpoints(seen),
                |s| &s.endpoints_synced,
                "endpoints",
            ));
        }
    } else {
        store.endpoints_synced.store(true, Ordering::Relaxed);
    }
    // pods
    if opts.watch_pods {
        let store = store.clone();
        let api: Api<Pod> = Api::all(client.clone());
        tokio::spawn(watch_loop(
            api,
            watcher::Config::default(),
            store,
            |s, o| s.apply_pod(o),
            |s, o| s.delete_pod(o),
            |s, seen| s.retain_pods(seen),
            |s| &s.pods_synced,
            "pods",
        ));
    } else {
        store.pods_synced.store(true, Ordering::Relaxed);
    }
    Ok(())
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
pub mod testing {
    use super::*;

    /// Populate a store directly (no API server) for handler tests.
    pub fn add_service(store: &Store, ns: &str, name: &str, ips: &[&str], ports: &[(&str, &str, u16)], headless: bool, external: Option<&str>) {
        let svc = Svc {
            name: name.into(),
            namespace: ns.into(),
            cluster_ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
            headless,
            external_name: external.map(|s| s.into()),
            ports: ports.iter().map(|(n, p, port)| Port { name: n.to_string(), protocol: p.to_string(), port: *port }).collect(),
            publish_not_ready: false,
        };
        let key = svc.key();
        for ip in &svc.cluster_ips {
            store.svc_by_ip.write().insert(*ip, key.clone());
        }
        store.services.write().insert(key, Arc::new(svc));
        store.namespaces.write().insert(ns.into());
    }

    pub fn add_endpoints(store: &Store, ns: &str, name: &str, eps: Vec<Endpoint>) {
        store.set_slice((ns.into(), name.into()), "slice".into(), eps);
    }

    pub fn add_pod(store: &Store, ns: &str, name: &str, ip: &str) {
        let key = (ns.to_string(), name.to_string());
        let ip: IpAddr = ip.parse().unwrap();
        store.pod_by_ip.write().insert(ip, key.clone());
        store.pods.write().insert(key.clone(), Arc::new(PodInfo { name: name.into(), namespace: ns.into(), ips: vec![ip] }));
        store.namespaces.write().insert(ns.into());
    }
}
