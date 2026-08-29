//! Global Prometheus registry and the core `coredns_*` metrics
//! (`plugin/metrics/vars`). Plugins register their own collectors with
//! `register()`; the `prometheus` plugin serves them.

use once_cell::sync::Lazy;
use prometheus::{
    core::Collector, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry,
};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// Register a collector, ignoring "already registered" (plugins are set up
/// once per server key and again on every reload).
pub fn register(c: Box<dyn Collector>) {
    if let Err(e) = REGISTRY.register(c) {
        match e {
            prometheus::Error::AlreadyReg => {}
            other => tracing::warn!("metrics: registering collector: {}", other),
        }
    }
}

fn counter_vec(sub: &str, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help).namespace("coredns").subsystem(sub), labels).unwrap();
    register(Box::new(c.clone()));
    c
}
fn gauge_vec(sub: &str, name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let c = IntGaugeVec::new(Opts::new(name, help).namespace("coredns").subsystem(sub), labels).unwrap();
    register(Box::new(c.clone()));
    c
}
fn histogram_vec(sub: &str, name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> HistogramVec {
    let c = HistogramVec::new(
        HistogramOpts::new(name, help).namespace("coredns").subsystem(sub).buckets(buckets),
        labels,
    )
    .unwrap();
    register(Box::new(c.clone()));
    c
}

pub fn time_buckets() -> Vec<f64> {
    // 0.00025s .. 8.192s, factor 2 (coredns plugin/pkg/response buckets)
    prometheus::exponential_buckets(0.00025, 2.0, 16).unwrap()
}
pub fn size_buckets() -> Vec<f64> {
    vec![0.0, 100.0, 200.0, 300.0, 400.0, 511.0, 1023.0, 2047.0, 4095.0, 8291.0, 16000.0, 32000.0, 48000.0, 64000.0]
}

pub static REQUEST_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    counter_vec("dns", "requests_total", "Counter of DNS requests made per zone, protocol and family.", &["server", "zone", "view", "proto", "family", "type"])
});
pub static REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    histogram_vec("dns", "request_duration_seconds", "Histogram of the time (in seconds) each request took per zone.", &["server", "zone", "view"], time_buckets())
});
pub static REQUEST_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    histogram_vec("dns", "request_size_bytes", "Size of the EDNS0 UDP buffer in bytes (64K for TCP) per zone and protocol.", &["server", "zone", "view", "proto"], size_buckets())
});
pub static REQUEST_DO: Lazy<IntCounterVec> = Lazy::new(|| {
    counter_vec("dns", "do_requests_total", "Counter of DNS requests with DO bit set per zone.", &["server", "zone", "view"])
});
pub static RESPONSE_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    histogram_vec("dns", "response_size_bytes", "Size of the returned response in bytes.", &["server", "zone", "view", "proto"], size_buckets())
});
pub static RESPONSE_RCODE: Lazy<IntCounterVec> = Lazy::new(|| {
    counter_vec("dns", "responses_total", "Counter of response status codes.", &["server", "zone", "view", "rcode", "plugin"])
});
pub static PANIC_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_panics_total", "A metrics that counts the number of panics.").unwrap();
    register(Box::new(c.clone()));
    c
});
pub static PLUGIN_ENABLED: Lazy<IntGaugeVec> = Lazy::new(|| {
    gauge_vec("", "plugin_enabled", "A metric that indicates whether a plugin is enabled on per server and zone basis.", &["server", "zone", "view", "name"])
});
pub static BUILD_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    gauge_vec("", "build_info", "A metric with a constant '1' value labeled by version, revision, and goversion from which CoreDNS was built.", &["version", "revision", "goversion"])
});
pub static HTTPS_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
    counter_vec("dns", "https_responses_total", "Counter of DoH responses per server and http status code.", &["server", "status"])
});
pub static QUIC_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
    counter_vec("dns", "quic_responses_total", "Counter of DoQ responses per server and QUIC application code.", &["server", "status"])
});
pub static HEALTH_DURATION: Lazy<Histogram> = Lazy::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new("coredns_health_request_duration_seconds", "Histogram of the time (in seconds) each request took.")
            .buckets(prometheus::exponential_buckets(0.00025, 2.0, 16).unwrap()),
    )
    .unwrap();
    register(Box::new(h.clone()));
    h
});
pub static HEALTH_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_health_request_failures_total", "The number of times the health check failed.").unwrap();
    register(Box::new(c.clone()));
    c
});
pub static RELOAD_FAILED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new("coredns_reload_failed_total", "Counter of the number of failed reload attempts.").unwrap();
    register(Box::new(c.clone()));
    c
});
pub static RELOAD_VERSION_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    gauge_vec("", "reload_version_info", "A metric with a constant '1' value labeled by hash, and value which type of hash generated.", &["hash", "value"])
});

pub fn init_build_info() {
    BUILD_INFO
        .with_label_values(&[env!("CARGO_PKG_VERSION"), option_env!("STORMCOREDNS_GIT_SHA").unwrap_or("unknown"), "rust"])
        .set(1);
}

pub fn gauge(name: &str, help: &str) -> IntGauge {
    let g = IntGauge::new(name, help).unwrap();
    register(Box::new(g.clone()));
    g
}
