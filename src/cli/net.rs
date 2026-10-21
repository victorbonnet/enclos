//! `enclos net`: a sandbox's network log and the destinations it was refused.

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Since;
use enclos::model::net::{DeniedDestination, NetEvent, Reason, Verdict, destination};
use enclos::model::now;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct NetArgs {
    #[command(subcommand)]
    verb: NetVerb,
}

#[derive(Subcommand)]
enum NetVerb {
    /// Every connection the sandbox made: one row per HTTPS tunnel, never its contents.
    Log {
        sandbox: SandboxName,
        /// Only connections from this far back, such as 30m, 12h or 7d.
        #[arg(long, value_name = "DURATION")]
        since: Option<Since>,
    },
    /// The destinations the sandbox was refused, to allow what you trust.
    Denied { sandbox: SandboxName },
}

pub fn run(engine: &Engine, args: NetArgs) -> Result<u8> {
    match args.verb {
        NetVerb::Log { sandbox, since } => {
            let from = since.and_then(|s| now().checked_sub(s.duration()).ok());
            print_log(&engine.net_log(&sandbox, from)?);
        }
        NetVerb::Denied { sandbox } => print_denied(&sandbox, &engine.net_denied(&sandbox)?),
    }
    Ok(exit::OK)
}

fn bytes(n: u64) -> String {
    match n {
        n if n >= 1_000_000 => format!("{:.1} MB", n as f64 / 1e6),
        n if n >= 1_000 => format!("{:.1} kB", n as f64 / 1e3),
        n => format!("{n} B"),
    }
}

fn print_log(events: &[NetEvent]) {
    if events.is_empty() {
        println!("No connections yet.");
        return;
    }
    println!(
        "{:<19}  {:<8}  {:<36}  {:<15}  {:>9}  {:>9}",
        "TIME (UTC)", "VERDICT", "DESTINATION", "ADDRESS", "UP", "DOWN"
    );
    for e in events {
        println!(
            "{:<19}  {:<8}  {:<36}  {:<15}  {:>9}  {:>9}",
            e.at.strftime("%Y-%m-%d %H:%M:%S"),
            verdict(e.verdict, e.reason),
            destination(&e.host, e.port),
            e.address.as_deref().unwrap_or("-"),
            bytes(e.bytes_up),
            bytes(e.bytes_down),
        );
    }
}

/// What became of a connection, as the log shows it.
fn verdict(verdict: Verdict, reason: Option<Reason>) -> String {
    match (verdict, reason) {
        (Verdict::Allowed, None) => "allowed".to_owned(),
        // The proxy closed a connection it had allowed: not a failure.
        (Verdict::Allowed, Some(Reason::Idle)) => "closed: idle".to_owned(),
        (Verdict::Allowed, Some(r)) => format!("failed: {r}"),
        (Verdict::Denied, Some(r)) => format!("denied: {r}"),
        (Verdict::Denied, None) => "denied".to_owned(),
    }
}

fn print_denied(sandbox: &SandboxName, denied: &[DeniedDestination]) {
    if denied.is_empty() {
        println!("Sandbox {sandbox} has not been refused anything.");
        return;
    }
    println!("Refused destinations of sandbox {sandbox}, most recent first:");
    for d in denied {
        let times = if d.count == 1 {
            "once".to_owned()
        } else {
            format!("{} times", d.count)
        };
        println!(
            "  {}  {}  {times}, last {}",
            destination(&d.host, d.port),
            d.reason,
            d.last.strftime("%Y-%m-%d %H:%M:%S UTC")
        );
    }
    println!("Allow what you trust with `enclos policy allow {sandbox} <destination>`.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_close_is_not_shown_as_a_failure() {
        let cases = [
            (Verdict::Allowed, None, "allowed"),
            (Verdict::Allowed, Some(Reason::Idle), "closed: idle"),
            (
                Verdict::Allowed,
                Some(Reason::ResolveFailed),
                "failed: resolve-failed",
            ),
            (
                Verdict::Denied,
                Some(Reason::NotAllowed),
                "denied: not-allowed",
            ),
            (Verdict::Denied, None, "denied"),
        ];
        for (v, r, shown) in cases {
            assert_eq!(verdict(v, r), shown);
        }
    }
}
