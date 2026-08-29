//! `timeouts { read DURATION; write DURATION; idle DURATION }` — stream
//! (TCP/TLS) server timeouts for this server block.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/timeouts: this plugin can only be used once per Server Block"));
        }
        if !c.remaining_args_until_brace().is_empty() {
            return Err(c.arg_err());
        }
        let mut any = false;
        while c.next_block() {
            let key = c.val().to_string();
            let a = c.remaining_args();
            if a.len() != 1 {
                return Err(c.arg_err());
            }
            let d = crate::dnsutil::parse_duration(&a[0]).map_err(|e| c.errf(format!("{}: {}", key, e)))?;
            if d.is_zero() || d > std::time::Duration::from_secs(86400) {
                return Err(c.errf(format!("{} timeout must be between 1 second and 24 hours", key)));
            }
            any = true;
            match key.as_str() {
                "read" => c.config.read_timeout = Some(d),
                "write" => c.config.write_timeout = Some(d),
                "idle" => c.config.idle_timeout = Some(d),
                o => return Err(c.errf(format!("unknown option '{}'", o))),
            }
        }
        if !any {
            return Err(c.errf("timeouts block with no timeouts specified"));
        }
    }
    Ok(())
}
