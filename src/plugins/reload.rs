//! `reload [INTERVAL] [JITTER]` — watches the Corefile and restarts the
//! server when its parsed contents change (imports included). Default
//! interval 30s, jitter 15s. `coredns_reload_version_info{hash="sha512"}`.

use crate::plugin::Controller;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// SHA-512 of the parsed Corefile, as CoreDNS hashes it: imports are
/// expanded (so editing an imported file reloads), and a Corefile that
/// does not parse is skipped until it does.
fn hash_file(p: &PathBuf) -> Option<String> {
    let blocks = match crate::corefile::parser::parse_file(p) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("plugin/reload: Corefile parse failed: {}", e);
            return None;
        }
    };
    let mut h = Sha512::new();
    h.update(format!("{:?}", blocks).as_bytes());
    Some(hex::encode(h.finalize()))
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut interval = Duration::from_secs(30);
    let mut jitter = Duration::from_secs(15);
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/reload: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        if args.len() > 2 {
            return Err(c.arg_err());
        }
        if let Some(i) = args.first() {
            interval = crate::dnsutil::parse_duration(i)?;
            if interval < Duration::from_secs(2) {
                interval = Duration::from_secs(2);
            }
        }
        if let Some(j) = args.get(1) {
            jitter = crate::dnsutil::parse_duration(j)?;
            if jitter < Duration::from_secs(1) {
                jitter = Duration::from_secs(1);
            }
        }
        if jitter > interval / 2 {
            jitter = interval / 2;
        }
    }
    let corefile: PathBuf = PathBuf::from(c.config.values.get("corefile").cloned().unwrap_or_else(|| "Corefile".into()));
    c.once_per_server_block(|c| {
        let (interval, jitter, corefile) = (interval, jitter, corefile.clone());
        // one watcher per instance, stopped by that instance's shutdown: after a
        // successful reload the old instance stops (and its watcher with it); after
        // a failed one the old instance keeps serving and keeps watching (#7)
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        c.on_shutdown(Box::new(move || {
            Box::pin(async move {
                stop.cancel();
                Ok(())
            })
        }));
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                let mut hash = hash_file(&corefile).unwrap_or_default();
                crate::metrics::RELOAD_VERSION_INFO.reset();
                crate::metrics::RELOAD_VERSION_INFO.with_label_values(&["sha512", &hash]).set(1);
                tokio::spawn(async move {
                    loop {
                        let j = rand::thread_rng().gen_range(0..=jitter.as_millis() as u64);
                        let wait = interval - jitter + Duration::from_millis(j);
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = tokio::time::sleep(wait) => {}
                        }
                        match hash_file(&corefile) {
                            Some(h) if h != hash => {
                                tracing::info!("plugin/reload: Corefile changed on disk, reloading");
                                // as in CoreDNS: take the new hash first, so a broken
                                // file is not retried until it changes again
                                hash = h;
                                crate::server::request_reload();
                            }
                            _ => {}
                        }
                    }
                });
                Ok(())
            })
        }));
        Ok(())
    })?;
    Ok(())
}
