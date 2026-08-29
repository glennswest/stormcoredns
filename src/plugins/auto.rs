//! `auto` — serves every zone file found in a directory, picking the
//! origin out of the file name with a regular expression.
//!
//! ```text
//! auto [ZONES...] {
//!     directory DIR [REGEXP ORIGIN_TEMPLATE]
//!     reload DURATION
//! }
//! ```
//! Default REGEXP is `db\.(.*)` and template `{1}`, so `db.example.org`
//! becomes zone `example.org.`.

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use crate::plugins::file::zone::Zone;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::rr::Record;
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct Auto {
    zones: Vec<String>,
    directory: PathBuf,
    re: Regex,
    template: String,
    loaded: ArcSwap<HashMap<String, Arc<Zone>>>,
}

impl Auto {
    /// Scan the directory and (re)load zones whose serial changed.
    fn walk(&self) {
        let mut next: HashMap<String, Arc<Zone>> = HashMap::new();
        let current = self.loaded.load();
        let Ok(rd) = std::fs::read_dir(&self.directory) else {
            tracing::warn!("plugin/auto: cannot read {}", self.directory.display());
            return;
        };
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        entries.sort();
        for path in entries {
            let fname = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let Some(caps) = self.re.captures(&fname) else { continue };
            let mut origin = self.template.clone();
            for i in 0..caps.len() {
                if let Some(m) = caps.get(i) {
                    origin = origin.replace(&format!("{{{}}}", i), m.as_str());
                }
            }
            let origin = crate::dnsutil::fqdn(&origin);
            if crate::plugin::zones_match(&self.zones, &origin).is_none() {
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("plugin/auto: reading {}: {}", path.display(), e);
                    continue;
                }
            };
            match Zone::parse(&text, &origin, Some(path.clone())) {
                Ok(z) => {
                    let changed = current.get(&origin).map(|old| old.serial != z.serial).unwrap_or(true);
                    if changed {
                        tracing::info!("plugin/auto: loaded zone {} from {} (serial {})", origin, path.display(), z.serial);
                        next.insert(origin.clone(), Arc::new(z));
                        if current.contains_key(&origin) {
                            crate::plugins::transfer::notify(&origin);
                        }
                    } else {
                        next.insert(origin.clone(), current.get(&origin).unwrap().clone());
                    }
                }
                Err(e) => tracing::error!("plugin/auto: {}: {}", path.display(), e),
            }
        }
        for gone in current.keys().filter(|k| !next.contains_key(*k)) {
            tracing::info!("plugin/auto: zone {} removed", gone);
        }
        self.loaded.store(Arc::new(next));
    }
}

#[async_trait]
impl Handler for Auto {
    fn name(&self) -> &'static str {
        "auto"
    }

    fn transfer(&self, zone: &str) -> Option<Vec<Record>> {
        self.loaded.load().get(zone).map(|z| z.all_records())
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let loaded = self.loaded.load();
        let names: Vec<String> = loaded.keys().cloned().collect();
        let Some(z) = crate::plugin::zones_match(&names, &qname) else {
            return next.serve(req).await;
        };
        let zone = loaded.get(z).unwrap().clone();
        drop(loaded);
        Ok(Reply::Msg(zone.lookup(req, true).await))
    }
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/auto: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        let zones = c.origins_from_args_or_server_block(&args)?;
        let mut directory: Option<PathBuf> = None;
        let mut re = Regex::new(r"db\.(.*)").unwrap();
        let mut template = "{1}".to_string();
        let mut reload = Duration::from_secs(60);
        while c.next_block() {
            match c.val() {
                "directory" => {
                    let a = c.remaining_args();
                    if a.is_empty() || a.len() == 2 || a.len() > 3 {
                        return Err(c.errf("directory needs DIR [REGEXP TEMPLATE]"));
                    }
                    let d = &a[0];
                    directory = Some(if std::path::Path::new(d).is_absolute() { PathBuf::from(d) } else { c.config.root.join(d) });
                    if a.len() == 3 {
                        re = Regex::new(&a[1]).map_err(|e| c.errf(format!("invalid regexp {}: {}", a[1], e)))?;
                        template = a[2].clone();
                    }
                }
                "reload" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    reload = crate::dnsutil::parse_duration(&a[0])?;
                }
                "upstream" => {
                    let _ = c.remaining_args();
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        let directory = directory.ok_or_else(|| c.errf("directory is required"))?;
        if !directory.is_dir() {
            tracing::warn!("plugin/auto: directory {} does not exist (yet)", directory.display());
        }
        let a = Arc::new(Auto { zones, directory, re, template, loaded: ArcSwap::from_pointee(HashMap::new()) });
        a.walk();
        c.add_plugin(a.clone());
        if !reload.is_zero() {
            let cancel = tokio_util::sync::CancellationToken::new();
            let stop = cancel.clone();
            c.on_startup(Box::new(move || {
                Box::pin(async move {
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = tokio::time::sleep(reload) => a.walk(),
                            }
                        }
                    });
                    Ok(())
                })
            }));
            c.on_shutdown(Box::new(move || {
                Box::pin(async move {
                    stop.cancel();
                    Ok(())
                })
            }));
        }
    }
    Ok(())
}
