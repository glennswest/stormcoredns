//! `on startup|shutdown COMMAND [ARGS...] [&]` — run a command when the
//! server starts or stops. A trailing `&` runs it in the background.

use crate::plugin::Controller;

fn run(cmd: Vec<String>, background: bool, event: &'static str) {
    let mut c = tokio::process::Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    if background {
        match c.spawn() {
            Ok(_) => tracing::info!("plugin/on: {} started {}", event, cmd.join(" ")),
            Err(e) => tracing::error!("plugin/on: {} {}: {}", event, cmd.join(" "), e),
        }
    } else {
        let cmdline = cmd.join(" ");
        tokio::spawn(async move {
            match c.output().await {
                Ok(o) => {
                    if !o.status.success() {
                        tracing::error!("plugin/on: {} {} exited with {}: {}", event, cmdline, o.status, String::from_utf8_lossy(&o.stderr).trim());
                    } else {
                        tracing::info!("plugin/on: {} {} ok", event, cmdline);
                    }
                }
                Err(e) => tracing::error!("plugin/on: {} {}: {}", event, cmdline, e),
            }
        });
    }
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
                        run(cmd, background, "startup");
                        Ok(())
                    })
                }));
            }
            "shutdown" => {
                let cmd = args.clone();
                c.on_shutdown(Box::new(move || {
                    Box::pin(async move {
                        run(cmd, background, "shutdown");
                        Ok(())
                    })
                }));
            }
            o => return Err(c.errf(format!("unknown event '{}'; expected startup or shutdown", o))),
        }
    }
    Ok(())
}
