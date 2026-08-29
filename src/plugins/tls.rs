//! `tls CERT KEY [CA] { client_auth MODE }` — the TLS material for
//! `tls://`, `https://`, `quic://` and `grpc://` server blocks.
//! MODE: `nocert` (default), `request`, `require`, `verify_if_given`,
//! `require_and_verify`.

use crate::plugin::Controller;
use crate::server::tls::{server_config, ClientAuth};
use std::path::PathBuf;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/tls: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        if args.len() < 2 || args.len() > 3 {
            return Err(c.errf("tls needs CERT KEY [CA]"));
        }
        let root = c.config.root.clone();
        let resolve = |p: &str| if std::path::Path::new(p).is_absolute() { PathBuf::from(p) } else { root.join(p) };
        let cert = resolve(&args[0]);
        let key = resolve(&args[1]);
        let ca = args.get(2).map(|p| resolve(p));
        let mut client_auth = ClientAuth::Nocert;
        while c.next_block() {
            match c.val() {
                "client_auth" => {
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    client_auth = ClientAuth::parse(&a[0]).ok_or_else(|| c.errf(format!("unknown authentication type '{}'", a[0])))?;
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if ca.is_none() && client_auth != ClientAuth::Nocert {
            return Err(c.errf("client_auth requires a CA certificate"));
        }
        let cfg = server_config(&cert, &key, ca.as_deref(), client_auth).map_err(|e| c.errf(e))?;
        c.config.tls = Some(cfg);
        c.config.values.insert("tls/client_auth".into(), format!("{:?}", client_auth));
    }
    Ok(())
}
