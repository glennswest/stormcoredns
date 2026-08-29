//! `root PATH` — the directory zone files (`file`, `auto`) are resolved
//! against.

use crate::plugin::Controller;
use std::path::PathBuf;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/root: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        if args.len() != 1 {
            return Err(c.arg_err());
        }
        let p = PathBuf::from(&args[0]);
        match std::fs::metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(c.errf(format!("root path is not a directory: {}", p.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("plugin/root: root directory {} does not exist", p.display());
            }
            Err(e) => return Err(c.errf(format!("unable to access root path {}: {}", p.display(), e))),
        }
        c.config.root = p;
    }
    Ok(())
}
