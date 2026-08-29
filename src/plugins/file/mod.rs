//! `file DBFILE [ZONES...] { reload DURATION }` — serves zones from RFC
//! 1035 master files, reloading when the SOA serial changes.

pub mod zone;

use crate::plugin::{Controller, DnsResult, Handler, Next, Reply, Request};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::OpCode;
use hickory_proto::rr::Record;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zone::Zone;

pub struct FileZone {
    pub origin: String,
    pub path: PathBuf,
    pub zone: ArcSwap<Zone>,
}

pub struct File {
    pub zones: Vec<Arc<FileZone>>,
    pub names: Vec<String>,
}

impl File {
    fn find(&self, qname: &str) -> Option<&Arc<FileZone>> {
        let z = crate::plugin::zones_match(&self.names, qname)?;
        self.zones.iter().find(|fz| fz.origin == z)
    }
}

#[async_trait]
impl Handler for File {
    fn name(&self) -> &'static str {
        "file"
    }

    fn transfer(&self, zone: &str) -> Option<Vec<Record>> {
        let fz = self.zones.iter().find(|fz| fz.origin == zone)?;
        Some(fz.zone.load().all_records())
    }

    async fn serve_dns(&self, req: &mut Request, next: Next<'_>) -> DnsResult {
        let qname = req.name();
        let Some(fz) = self.find(&qname) else {
            return next.serve(req).await;
        };
        if req.msg.op_code() == OpCode::Notify {
            // we are primary for this zone; acknowledge and ignore
            let m = req.new_reply();
            return Ok(Reply::Msg(m));
        }
        let z = fz.zone.load();
        let m = z.lookup(req, true).await;
        Ok(Reply::Msg(m))
    }
}

pub fn load(path: &PathBuf, origin: &str) -> anyhow::Result<Zone> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("opening {}: {}", path.display(), e))?;
    Zone::parse(&text, origin, Some(path.clone()))
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut zones: Vec<Arc<FileZone>> = Vec::new();
    let mut reload = Duration::from_secs(60);
    while c.next() {
        let mut args = c.remaining_args_until_brace();
        if args.is_empty() {
            return Err(c.arg_err());
        }
        let file = args.remove(0);
        let path = if std::path::Path::new(&file).is_absolute() { PathBuf::from(&file) } else { c.config.root.join(&file) };
        let origins = c.origins_from_args_or_server_block(&args)?;
        while c.next_block() {
            match c.val() {
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
        for origin in origins {
            let z = load(&path, &origin).map_err(|e| c.errf(e))?;
            tracing::info!("plugin/file: loaded zone {} from {} (serial {}, {} records)", origin, path.display(), z.serial, z.len());
            zones.push(Arc::new(FileZone { origin, path: path.clone(), zone: ArcSwap::from_pointee(z) }));
        }
    }
    let names: Vec<String> = zones.iter().map(|z| z.origin.clone()).collect();
    let f = Arc::new(File { zones: zones.clone(), names });
    c.add_plugin(f);
    if !reload.is_zero() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        c.on_startup(Box::new(move || {
            Box::pin(async move {
                for fz in zones {
                    let cancel = cancel.clone();
                    tokio::spawn(async move {
                        let mut last_mtime = std::fs::metadata(&fz.path).and_then(|m| m.modified()).ok();
                        loop {
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = tokio::time::sleep(reload) => {}
                            }
                            let mtime = std::fs::metadata(&fz.path).and_then(|m| m.modified()).ok();
                            if mtime == last_mtime {
                                continue;
                            }
                            last_mtime = mtime;
                            match load(&fz.path, &fz.origin) {
                                Ok(z) => {
                                    let old = fz.zone.load().serial;
                                    if z.serial != old {
                                        tracing::info!("plugin/file: successfully reloaded zone {} in {} with serial {}", fz.origin, fz.path.display(), z.serial);
                                        fz.zone.store(Arc::new(z));
                                        crate::plugins::transfer::notify(&fz.origin);
                                    }
                                }
                                Err(e) => tracing::error!("plugin/file: failed to reload zone {} in {}: {}", fz.origin, fz.path.display(), e),
                            }
                        }
                    });
                }
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
    Ok(())
}
