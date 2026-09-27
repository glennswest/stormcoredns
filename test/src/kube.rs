//! The apiserver, with the run's service-account token, in the run's own
//! namespace. Everything created carries `storm.io/test-run=<run id>`.

use crate::env::Env;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct Kube {
    http: reqwest::Client,
    base: String,
    token: String,
    pub ns: String,
    run: String,
}

impl Kube {
    pub fn new(env: &Env) -> Result<Kube> {
        let ca = reqwest::Certificate::from_pem(&env.ca).context("the service-account ca.crt is not PEM")?;
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(Kube { http, base: env.api.clone(), token: env.token.clone(), ns: env.namespace.clone(), run: env.run_id.clone() })
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        let mut r = self.http.request(method.clone(), format!("{}{}", self.base, path)).bearer_auth(&self.token);
        if let Some(b) = body {
            r = r.json(b);
        }
        let resp = r.send().await.with_context(|| format!("{method} {path}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }

    pub async fn get(&self, path: &str) -> Result<Option<Value>> {
        match self.call(reqwest::Method::GET, path, None).await? {
            (404, _) => Ok(None),
            (s, v) if (200..300).contains(&s) => Ok(Some(v)),
            (s, v) => bail!("GET {path}: {s} {}", brief(&v)),
        }
    }

    pub async fn create(&self, path: &str, body: Value) -> Result<Value> {
        match self.call(reqwest::Method::POST, path, Some(&body)).await? {
            (s, v) if (200..300).contains(&s) => Ok(v),
            (s, v) => bail!("POST {path}: {s} {}", brief(&v)),
        }
    }

    /// Delete; already gone is fine.
    pub async fn delete(&self, path: &str) -> Result<()> {
        match self.call(reqwest::Method::DELETE, path, None).await? {
            (404, _) => Ok(()),
            (s, _) if (200..300).contains(&s) => Ok(()),
            (s, v) => bail!("DELETE {path}: {s} {}", brief(&v)),
        }
    }

    /// The API answers, and this run may work in its namespace.
    pub async fn preflight(&self) -> Result<()> {
        self.get(&format!("/api/v1/namespaces/{}/services", self.ns))
            .await?
            .ok_or_else(|| anyhow!("the run's namespace {} does not exist", self.ns))?;
        Ok(())
    }

    fn meta(&self, name: &str) -> Value {
        json!({"name": name, "namespace": self.ns, "labels": {"storm.io/test-run": self.run}})
    }

    fn services(&self) -> String {
        format!("/api/v1/namespaces/{}/services", self.ns)
    }

    /// A ClusterIP Service with no selector. Returns its ClusterIP.
    pub async fn cluster_ip_service(&self, name: &str, ports: &[Port]) -> Result<IpAddr> {
        let body = json!({"apiVersion": "v1", "kind": "Service", "metadata": self.meta(name),
                          "spec": {"type": "ClusterIP", "ports": ports_json(ports, true)}});
        let v = self.create(&self.services(), body).await?;
        self.cluster_ip_of(name, &v).await
    }

    async fn cluster_ip_of(&self, name: &str, created: &Value) -> Result<IpAddr> {
        let start = Instant::now();
        let mut v = created.clone();
        loop {
            if let Some(ip) = v["spec"]["clusterIP"].as_str().filter(|s| !s.is_empty() && *s != "None") {
                return ip.parse().with_context(|| format!("service {name}: clusterIP {ip}"));
            }
            if start.elapsed() > Duration::from_secs(10) {
                bail!("service {name} was given no clusterIP within 10 s");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            v = self.get(&format!("{}/{name}", self.services())).await?.unwrap_or_default();
        }
    }

    /// A headless Service (no selector) backed by `addrs`, written both as
    /// core Endpoints and as an EndpointSlice, so the plugin sees it
    /// whichever of the two it watches.
    pub async fn headless_service(&self, name: &str, ports: &[Port], addrs: &[Addr]) -> Result<()> {
        let body = json!({"apiVersion": "v1", "kind": "Service", "metadata": self.meta(name),
                          "spec": {"clusterIP": "None", "ports": ports_json(ports, true)}});
        self.create(&self.services(), body).await?;
        self.set_endpoints(name, ports, addrs).await
    }

    /// Replace the backends of `name` (delete and create both kinds).
    pub async fn set_endpoints(&self, name: &str, ports: &[Port], addrs: &[Addr]) -> Result<()> {
        let ns = &self.ns;
        self.delete(&format!("/api/v1/namespaces/{ns}/endpoints/{name}")).await?;
        let slice_path = format!("/apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices");
        let slice_name = format!("{name}-test");
        // An API without EndpointSlices is allowed (the plugin falls back).
        let has_slices = self.get(&slice_path).await.map(|v| v.is_some()).unwrap_or(false);
        if has_slices {
            self.delete(&format!("{slice_path}/{slice_name}")).await?;
        }
        let ep_addrs: Vec<Value> = addrs
            .iter()
            .map(|a| match &a.hostname {
                Some(h) => json!({"ip": a.ip.to_string(), "hostname": h}),
                None => json!({"ip": a.ip.to_string()}),
            })
            .collect();
        self.create(
            &format!("/api/v1/namespaces/{ns}/endpoints"),
            json!({"apiVersion": "v1", "kind": "Endpoints", "metadata": self.meta(name),
                   "subsets": [{"addresses": ep_addrs, "ports": ports_json(ports, false)}]}),
        )
        .await?;
        if has_slices {
            let mut meta = self.meta(&slice_name);
            meta["labels"]["kubernetes.io/service-name"] = json!(name);
            let eps: Vec<Value> = addrs
                .iter()
                .map(|a| {
                    let mut e = json!({"addresses": [a.ip.to_string()], "conditions": {"ready": true}});
                    if let Some(h) = &a.hostname {
                        e["hostname"] = json!(h);
                    }
                    e
                })
                .collect();
            let family = if addrs.first().map(|a| a.ip.is_ipv6()).unwrap_or(false) { "IPv6" } else { "IPv4" };
            self.create(&slice_path, json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": meta,
                                            "addressType": family, "endpoints": eps, "ports": ports_json(ports, false)}))
                .await?;
        }
        Ok(())
    }

    pub async fn external_name_service(&self, name: &str, target: &str) -> Result<()> {
        let body = json!({"apiVersion": "v1", "kind": "Service", "metadata": self.meta(name),
                          "spec": {"type": "ExternalName", "externalName": target}});
        self.create(&self.services(), body).await?;
        Ok(())
    }

    /// Delete a Service and any backends this run gave it.
    pub async fn delete_service(&self, name: &str) -> Result<()> {
        let ns = &self.ns;
        self.delete(&format!("{}/{name}", self.services())).await?;
        self.delete(&format!("/api/v1/namespaces/{ns}/endpoints/{name}")).await?;
        let _ = self.delete(&format!("/apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices/{name}-test")).await;
        Ok(())
    }
}

pub struct Port {
    pub name: &'static str,
    pub port: u16,
    pub protocol: &'static str,
}

pub struct Addr {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

fn ports_json(ports: &[Port], service: bool) -> Vec<Value> {
    ports
        .iter()
        .map(|p| {
            let mut v = json!({"name": p.name, "port": p.port, "protocol": p.protocol});
            if service {
                v["targetPort"] = json!(p.port);
            }
            v
        })
        .collect()
}

fn brief(v: &Value) -> String {
    v["message"].as_str().map(str::to_string).unwrap_or_else(|| {
        let s = v.to_string();
        s.chars().take(300).collect()
    })
}
