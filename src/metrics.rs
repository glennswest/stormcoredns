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

// ------------------------------------------------------- process metrics

/// The `process_*` metrics of the Go client's process collector (the
/// stock CoreDNS dashboard graphs them), read from `/proc/self` on each
/// scrape. Linux only; elsewhere nothing is reported.
pub struct ProcessCollector {
    cpu: prometheus::Counter,
    open_fds: prometheus::Gauge,
    max_fds: prometheus::Gauge,
    vsize: prometheus::Gauge,
    vsize_max: prometheus::Gauge,
    rss: prometheus::Gauge,
    start: prometheus::Gauge,
    descs: Vec<prometheus::core::Desc>,
}

impl ProcessCollector {
    pub fn new() -> ProcessCollector {
        let g = |n: &str, h: &str| prometheus::Gauge::new(n, h).unwrap();
        let cpu = prometheus::Counter::new("process_cpu_seconds_total", "Total user and system CPU time spent in seconds.").unwrap();
        let open_fds = g("process_open_fds", "Number of open file descriptors.");
        let max_fds = g("process_max_fds", "Maximum number of open file descriptors.");
        let vsize = g("process_virtual_memory_bytes", "Virtual memory size in bytes.");
        let vsize_max = g("process_virtual_memory_max_bytes", "Maximum amount of virtual memory available in bytes.");
        let rss = g("process_resident_memory_bytes", "Resident memory size in bytes.");
        let start = g("process_start_time_seconds", "Start time of the process since unix epoch in seconds.");
        let mut descs = Vec::new();
        descs.extend(cpu.desc().into_iter().cloned());
        for x in [&open_fds, &max_fds, &vsize, &vsize_max, &rss, &start] {
            descs.extend(x.desc().into_iter().cloned());
        }
        ProcessCollector { cpu, open_fds, max_fds, vsize, vsize_max, rss, start, descs }
    }

    fn refresh(&self) -> Option<()> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // fields after "(comm) ": state is field 3, so field N is f[N - 3]
        let f: Vec<&str> = stat.get(stat.rfind(')')? + 2..)?.split_whitespace().collect();
        let num = |i: usize| f.get(i - 3).and_then(|v| v.parse::<f64>().ok());
        // SAFETY: sysconf has no preconditions
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;
        let cpu = (num(14)? + num(15)?) / ticks;
        let delta = cpu - self.cpu.get();
        if delta > 0.0 {
            self.cpu.inc_by(delta);
        }
        self.vsize.set(num(23)?);
        self.rss.set(num(24)? * page);
        let btime = std::fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<f64>().ok()))?;
        self.start.set(btime + num(22)? / ticks);
        if let Ok(d) = std::fs::read_dir("/proc/self/fd") {
            self.open_fds.set(d.count() as f64);
        }
        let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
        let soft = |prefix: &str| {
            limits.lines().find(|l| l.starts_with(prefix)).and_then(|l| l[prefix.len()..].split_whitespace().next()).map(|v| v.parse::<f64>().unwrap_or(u64::MAX as f64))
        };
        if let Some(v) = soft("Max open files") {
            self.max_fds.set(v);
        }
        if let Some(v) = soft("Max address space") {
            self.vsize_max.set(v);
        }
        Some(())
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ProcessCollector {
    fn desc(&self) -> Vec<&prometheus::core::Desc> {
        self.descs.iter().collect()
    }

    fn collect(&self) -> Vec<prometheus::proto::MetricFamily> {
        if self.refresh().is_none() {
            return Vec::new();
        }
        let mut out = self.cpu.collect();
        for x in [&self.open_fds, &self.max_fds, &self.vsize, &self.vsize_max, &self.rss, &self.start] {
            out.extend(x.collect());
        }
        out
    }
}

/// Register the process collector once.
pub fn init_process_metrics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| register(Box::new(ProcessCollector::new())));
}

#[cfg(test)]
mod process_tests {
    use super::*;

    #[test]
    fn reads_proc_self() {
        let p = ProcessCollector::new();
        let fams = p.collect();
        if cfg!(target_os = "linux") {
            let names: Vec<&str> = fams.iter().map(|f| f.get_name()).collect();
            for n in ["process_cpu_seconds_total", "process_open_fds", "process_max_fds", "process_resident_memory_bytes", "process_start_time_seconds", "process_virtual_memory_bytes"] {
                assert!(names.contains(&n), "{} missing from {:?}", n, names);
            }
            assert!(p.rss.get() > 0.0 && p.open_fds.get() > 0.0 && p.start.get() > 1.6e9);
        }
    }
}
