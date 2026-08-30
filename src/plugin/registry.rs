//! The directive registry: CoreDNS's `plugin.cfg`.
//!
//! The order below is the order plugins run in the chain, regardless of
//! the order they appear in a Corefile. Names not in this list are unknown
//! directives.

use super::Controller;

pub type SetupFn = fn(&mut Controller<'_>) -> anyhow::Result<()>;

pub struct DirectiveDef {
    pub name: &'static str,
    /// `None` = recognised but not implemented in this build.
    pub setup: Option<SetupFn>,
}

macro_rules! directives {
    ( $( $name:literal => $setup:expr ),* $(,)? ) => {
        pub static ORDER: &[DirectiveDef] = &[
            $( DirectiveDef { name: $name, setup: $setup } ),*
        ];
    };
}

directives! {
    "root"        => Some(crate::plugins::root::setup),
    "metadata"    => Some(crate::plugins::metadata::setup),
    "geoip"       => Some(crate::plugins::geoip::setup),
    "cancel"      => Some(crate::plugins::cancel::setup),
    "tls"         => Some(crate::plugins::tls::setup),
    "timeouts"    => Some(crate::plugins::timeouts::setup),
    "multisocket" => Some(crate::plugins::multisocket::setup),
    "reload"      => Some(crate::plugins::reload::setup),
    "nsid"        => Some(crate::plugins::nsid::setup),
    "bufsize"     => Some(crate::plugins::bufsize::setup),
    "bind"        => Some(crate::plugins::bind::setup),
    "debug"       => Some(crate::plugins::debug::setup),
    "trace"       => Some(crate::plugins::trace::setup),
    "ready"       => Some(crate::plugins::ready::setup),
    "health"      => Some(crate::plugins::health::setup),
    "pprof"       => Some(crate::plugins::pprof::setup),
    "prometheus"  => Some(crate::plugins::metrics::setup),
    "errors"      => Some(crate::plugins::errors::setup),
    "log"         => Some(crate::plugins::log::setup),
    "dnstap"      => Some(crate::plugins::dnstap::setup),
    "local"       => Some(crate::plugins::local::setup),
    "dns64"       => Some(crate::plugins::dns64::setup),
    "acl"         => Some(crate::plugins::acl::setup),
    "any"         => Some(crate::plugins::any::setup),
    "chaos"       => Some(crate::plugins::chaos::setup),
    "loadbalance" => Some(crate::plugins::loadbalance::setup),
    "tsig"        => Some(crate::plugins::tsig::setup),
    "cache"       => Some(crate::plugins::cache::setup),
    "rewrite"     => Some(crate::plugins::rewrite::setup),
    "header"      => Some(crate::plugins::header::setup),
    "dnssec"      => Some(crate::plugins::dnssec::setup),
    "autopath"    => Some(crate::plugins::autopath::setup),
    "minimal"     => Some(crate::plugins::minimal::setup),
    "template"    => Some(crate::plugins::template::setup),
    "transfer"    => Some(crate::plugins::transfer::setup),
    "hosts"       => Some(crate::plugins::hosts::setup),
    "route53"     => Some(crate::plugins::route53::setup),
    "azure"       => Some(crate::plugins::azure::setup),
    "clouddns"    => Some(crate::plugins::clouddns::setup),
    "k8s_external"=> Some(crate::plugins::k8s_external::setup),
    "kubernetes"  => Some(crate::plugins::kubernetes::setup),
    "file"        => Some(crate::plugins::file::setup),
    "auto"        => Some(crate::plugins::auto::setup),
    "secondary"   => Some(crate::plugins::secondary::setup),
    "etcd"        => Some(crate::plugins::etcd::setup),
    "loop"        => Some(crate::plugins::r#loop::setup),
    "forward"     => Some(crate::plugins::forward::setup),
    "grpc"        => Some(crate::plugins::grpc::setup),
    "erratic"     => Some(crate::plugins::erratic::setup),
    "whoami"      => Some(crate::plugins::whoami::setup),
    "on"          => Some(crate::plugins::on::setup),
    "sign"        => Some(crate::plugins::sign::setup),
    "view"        => Some(crate::plugins::view::setup),
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
