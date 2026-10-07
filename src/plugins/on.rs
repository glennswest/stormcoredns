//! `on startup|shutdown COMMAND [ARGS...] [&]` — run a command when the
//! server starts or stops. As in CoreDNS (caddy's onevent), the command is
//! waited for, and a failure (it cannot start, or exits non-zero) fails
//! the startup/shutdown hook; a trailing `&` runs it in the background.

use crate::plugin::Controller;

async fn run(cmd: Vec<String>, background: bool, event: &'static str) -> anyhow::Result<()> {
    let mut c = tokio::process::Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    let cmdline = cmd.join(" ");
    if background {
        match c.spawn() {
            Ok(_) => tracing::info!("plugin/on: {} started {}", event, cmdline),
            Err(e) => tracing::error!("plugin/on: {} {}: {}", event, cmdline, e),
        }
        return Ok(());
    }
    let o = c.output().await.map_err(|e| anyhow::anyhow!("plugin/on: {} {}: {}", event, cmdline, e))?;
    if !o.status.success() {
        anyhow::bail!("plugin/on: {} {} exited with {}: {}", event, cmdline, o.status, String::from_utf8_lossy(&o.stderr).trim());
    }
    tracing::info!("plugin/on: {} {} ok", event, cmdline);
    Ok(())
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    while c.next() {
        let mut args = c.remaining_args();
        if args.len() < 2 {
            return Err(c.errf("on EVENT COMMAND [ARGS...] [&] expected"));
        }
        let event = args.remove(0);
        let background = args.last().map(|s| s == "&").unwrap_or(false);
        if background {
            args.pop();
        }
        match event.as_str() {
            "startup" => {
                let cmd = args.clone();
                c.on_startup(Box::new(move || {
                    Box::pin(async move {
                        run(cmd, background, "startup").await
                    })
                }));
            }
            "shutdown" => {
                let cmd = args.clone();
                c.on_shutdown(Box::new(move || {
                    Box::pin(async move {
                        run(cmd, background, "shutdown").await
                    })
                }));
            }
            o => return Err(c.errf(format!("unknown event '{}'; expected startup or shutdown", o))),
        }
    }
    Ok(())
}
