//! `enclos dashboard <sandbox>`: the runtime's dashboard, for the user
//! running it, until Ctrl-C (ADR 0040). Its address goes to stdout, as
//! text or, with `--json`, as one JSON line, and enclos's own words to
//! stderr, as for `connect`.

use std::io::Write;

use clap::Args;

use enclos::engine::{DashboardOpen, Engine};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct DashboardArgs {
    sandbox: SandboxName,
}

pub fn run(engine: &Engine, by: &Actor, args: DashboardArgs) -> Result<u8> {
    let sandbox = &args.sandbox;
    let ended = engine.dashboard(by, sandbox, &mut say_open)?;
    let mut end = ended.end;
    if ended.failed.is_none() {
        // Stopped as it was told: the signal that ended it is no news.
        end.signal = None;
    }
    super::connect::report_end(sandbox, &end);
    match ended.failed {
        None => {
            super::output::note(&format!(
                "the dashboard of sandbox {sandbox} is closed, and session {} ended",
                end.session
            ));
            Ok(exit::OK)
        }
        Some(what) => Err(Error::Dashboard { what }),
    }
}

/// Says where the dashboard is, once it serves.
fn say_open(open: &DashboardOpen) {
    let mut out = std::io::stdout();
    let shown = match super::output::json() {
        true => super::output::line(&serde_json::json!({
            "dashboard": {
                "sandbox": open.sandbox.as_str(),
                "session": open.session.0,
                "url": open.url,
                "port": open.port,
                "uid": open.user,
            }
        })),
        false => open.url.clone(),
    };
    let _ = writeln!(out, "{shown}");
    let _ = out.flush();
    super::output::note(&how_to_open(open));
}

/// What the user is told besides the address.
fn how_to_open(open: &DashboardOpen) -> String {
    let port = open.port;
    format!(
        "the dashboard of sandbox {} serves only you (uid {}), until Ctrl-C; on a remote host, run `ssh -L {port}:127.0.0.1:{port} <host>` on your own machine, then open the address there",
        open.sandbox, open.user
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_is_told_who_it_serves_and_how_to_reach_it_from_afar() {
        let open = DashboardOpen {
            sandbox: "lab".parse().unwrap(),
            session: enclos::model::session::SessionId(12),
            port: 41003,
            url: "http://127.0.0.1:41003/".to_owned(),
            user: 1000,
        };
        assert_eq!(
            how_to_open(&open),
            "the dashboard of sandbox lab serves only you (uid 1000), until Ctrl-C; on a remote host, run `ssh -L 41003:127.0.0.1:41003 <host>` on your own machine, then open the address there"
        );
    }
}
