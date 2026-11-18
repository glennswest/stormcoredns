//! The directive registry: CoreDNS's `plugin.cfg`.
//!
//! The order below is the order plugins run in the chain, regardless of
//! the order they appear in a Corefile. Names not in this list are unknown
//! directives.

use super::Controller;

pub type SetupFn = fn(&mut Controller<'_>) -> anyhow::Result<()>;

pub struct DirectiveDef {
    pub name: &'static str,
    pub setup: SetupFn,
}

macro_rules! directives {
    ( $( $name:literal => $setup:expr ),* $(,)? ) => {
        pub static ORDER: &[DirectiveDef] = &[
            $( DirectiveDef { name: $name, setup: $setup } ),*
        ];
    };
}

directives! {
    "root"        => crate::plugins::root::setup,
    "metadata"    => crate::plugins::metadata::setup,
    "geoip"       => crate::plugins::geoip::setup,
    "cancel"      => crate::plugins::cancel::setup,
    "tls"         => crate::plugins::tls::setup,
    "timeouts"    => crate::plugins::timeouts::setup,
    "multisocket" => crate::plugins::multisocket::setup,
    "reload"      => crate::plugins::reload::setup,
    "nsid"        => crate::plugins::nsid::setup,
    "bufsize"     => crate::plugins::bufsize::setup,
    "bind"        => crate::plugins::bind::setup,
    "debug"       => crate::plugins::debug::setup,
    "trace"       => crate::plugins::trace::setup,
    "ready"       => crate::plugins::ready::setup,
    "health"      => crate::plugins::health::setup,
    "pprof"       => crate::plugins::pprof::setup,
    "prometheus"  => crate::plugins::metrics::setup,
    "errors"      => crate::plugins::errors::setup,
    "log"         => crate::plugins::log::setup,
    "dnstap"      => crate::plugins::dnstap::setup,
    "local"       => crate::plugins::local::setup,
    "dns64"       => crate::plugins::dns64::setup,
    "acl"         => crate::plugins::acl::setup,
    "any"         => crate::plugins::any::setup,
    "chaos"       => crate::plugins::chaos::setup,
    "loadbalance" => crate::plugins::loadbalance::setup,
    "tsig"        => crate::plugins::tsig::setup,
    "cache"       => crate::plugins::cache::setup,
    "rewrite"     => crate::plugins::rewrite::setup,
    "header"      => crate::plugins::header::setup,
    "dnssec"      => crate::plugins::dnssec::setup,
    "autopath"    => crate::plugins::autopath::setup,
    "minimal"     => crate::plugins::minimal::setup,
    "template"    => crate::plugins::template::setup,
    "transfer"    => crate::plugins::transfer::setup,
    "hosts"       => crate::plugins::hosts::setup,
    "route53"     => crate::plugins::route53::setup,
    "azure"       => crate::plugins::azure::setup,
    "clouddns"    => crate::plugins::clouddns::setup,
    "k8s_external"=> crate::plugins::k8s_external::setup,
    "kubernetes"  => crate::plugins::kubernetes::setup,
    "file"        => crate::plugins::file::setup,
    "auto"        => crate::plugins::auto::setup,
    "secondary"   => crate::plugins::secondary::setup,
    "etcd"        => crate::plugins::etcd::setup,
    "loop"        => crate::plugins::r#loop::setup,
    "forward"     => crate::plugins::forward::setup,
    "grpc"        => crate::plugins::grpc::setup,
    "erratic"     => crate::plugins::erratic::setup,
    "whoami"      => crate::plugins::whoami::setup,
    "on"          => crate::plugins::on::setup,
    "sign"        => crate::plugins::sign::setup,
    "view"        => crate::plugins::view::setup,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The order must match CoreDNS's plugin.cfg: backends that answer
    /// authoritatively (kubernetes, file, etcd...) run before `forward`,
    /// otherwise `forward .` swallows every query (issue #1).
    #[test]
    fn plugin_cfg_order() {
        let pos = |n: &str| position(n).unwrap();
        assert!(pos("kubernetes") < pos("forward"));
        assert!(pos("k8s_external") < pos("kubernetes"));
        assert!(pos("hosts") < pos("route53"));
        assert!(pos("kubernetes") < pos("file"));
        assert!(pos("etcd") < pos("loop"));
        assert!(pos("loop") < pos("forward"));
        assert!(pos("cache") < pos("kubernetes"));
        assert!(pos("prometheus") < pos("errors"));
        assert!(pos("sign") < pos("view"));
        assert_eq!(ORDER.len(), 53);
    }
}

pub fn lookup(name: &str) -> Option<&'static DirectiveDef> {
    ORDER.iter().find(|d| d.name == name)
}

pub fn names() -> Vec<&'static str> {
    ORDER.iter().map(|d| d.name).collect()
}

/// Position of a directive in the chain order (for sorting).
pub fn position(name: &str) -> Option<usize> {
    ORDER.iter().position(|d| d.name == name)
}
