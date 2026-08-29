//! `reload [INTERVAL] [JITTER]` — watches the Corefile and restarts the
//! server when its contents change. Default interval 30s, jitter 15s.

use crate::plugin::Controller;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The watcher of the current instance (only one per process).
static WATCHER: Lazy<Mutex<Option<CancellationToken>>> = Lazy::new(|| Mutex::new(None));

fn hash_file(p: &PathBuf) -> Option<String> {
    let data = std::fs::read(p).ok()?;
    let mut h = Sha256::new();
    h.update(&data);
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
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                let cancel = CancellationToken::new();
                {
                    let mut w = WATCHER.lock();
                    if let Some(old) = w.take() {
                        old.cancel();
                    }
                    *w = Some(cancel.clone());
                }
                let start_hash = hash_file(&corefile).unwrap_or_default();
                crate::metrics::RELOAD_VERSION_INFO.reset();
                crate::metrics::RELOAD_VERSION_INFO.with_label_values(&["sha256", &start_hash]).set(1);
                tokio::spawn(async move {
                    loop {
                        let j = rand::thread_rng().gen_range(0..=jitter.as_millis() as u64);
                        let wait = interval - jitter + Duration::from_millis(j);
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = tokio::time::sleep(wait) => {}
                        }
                        match hash_file(&corefile) {
                            Some(h) if h != start_hash => {
                                tracing::info!("plugin/reload: Corefile changed on disk, reloading");
                                crate::server::request_reload();
                                return;
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
