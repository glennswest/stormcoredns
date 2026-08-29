//! `multisocket [NUM_SOCKETS]` — open several SO_REUSEPORT listening
//! sockets per address so the kernel spreads incoming queries across
//! them. Default: number of CPUs.

use crate::plugin::Controller;

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/multisocket: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args();
        let num = match args.len() {
            0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            1 => {
                let v: usize = args[0].parse().map_err(|_| c.errf(format!("invalid num sockets: {}", args[0])))?;
                if v == 0 {
                    return Err(c.errf("num sockets can not be zero"));
                }
                v
            }
            _ => return Err(c.arg_err()),
        };
        c.config.num_sockets = num;
    }
    Ok(())
}
