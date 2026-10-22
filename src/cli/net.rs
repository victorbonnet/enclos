//! `enclos net`: a sandbox's network log and the destinations it was refused.

use clap::{Args, Subcommand};

use enclos::engine::Engine;
use enclos::error::{Result, exit};
use enclos::model::audit::Since;
use enclos::model::net::{DeniedDestination, NameSeen, NetEvent, Reason, Verdict, destination};
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
    // As wide as the longest verdict, such as `denied: name-mismatch`.
    let wide = events
        .iter()
        .map(|e| verdict(e.verdict, e.reason).len())
        .max()
        .unwrap_or(0)
        .max("VERDICT".len());
    println!(
        "{:<19}  {:<wide$}  {:<36}  {:<15}  {:>9}  {:>9}  SERVER NAME",
        "TIME (UTC)", "VERDICT", "DESTINATION", "ADDRESS", "UP", "DOWN"
    );
    for e in events {
        println!(
            "{:<19}  {:<wide$}  {:<36}  {:<15}  {:>9}  {:>9}  {}",
            e.at.strftime("%Y-%m-%d %H:%M:%S"),
            verdict(e.verdict, e.reason),
            destination(&e.host, e.port),
            e.address.as_deref().unwrap_or("-"),
            bytes(e.bytes_up),
            bytes(e.bytes_down),
            server_name(e),
        );
    }
}

/// What a tunnel's ClientHello showed of the server it asked for, as the
/// log shows it (design §6, server name check).
fn server_name(e: &NetEvent) -> String {
    match (e.name_seen, e.server_name.as_deref()) {
        (Some(NameSeen::Name), Some(name)) => name.to_owned(),
        (Some(NameSeen::Encrypted), Some(public)) => format!("hidden (ECH), public name {public}"),
        (Some(NameSeen::Encrypted), None) => "hidden (ECH)".to_owned(),
        (Some(NameSeen::NotTls), _) => "not TLS".to_owned(),
        (Some(NameSeen::Unreadable), _) => "unreadable hello".to_owned(),
        (Some(NameSeen::Name | NameSeen::NoName), _) => "no name seen".to_owned(),
        // Plain HTTP, or a tunnel whose client sent nothing.
        (None, _) => "-".to_owned(),
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
    print!("{}", denied_text(sandbox, denied));
}

fn denied_text(sandbox: &SandboxName, denied: &[DeniedDestination]) -> String {
    if denied.is_empty() {
        return format!("Sandbox {sandbox} has not been refused anything.\n");
    }
    let mut out = format!("Refused destinations of sandbox {sandbox}, most recent first:\n");
    for d in denied {
        let times = if d.count == 1 {
            "once".to_owned()
        } else {
            format!("{} times", d.count)
        };
        out.push_str(&format!(
            "  {}  {}  {times}, last {}\n",
            destination(&d.host, d.port),
            d.reason,
            d.last.strftime("%Y-%m-%d %H:%M:%S UTC")
        ));
    }
    if denied.iter().any(|d| !d.reason.nothing_to_allow()) {
        out.push_str(&format!(
            "Allow what you trust with `enclos policy allow {sandbox} <destination>`.\n"
        ));
    }
    if denied.iter().any(|d| d.reason == Reason::BadRequest) {
        out.push_str(&format!(
            "{}: the request was malformed or framed in a way the proxy does not forward, whatever the destination; there is nothing to allow.\n",
            Reason::BadRequest
        ));
    }
    if denied
        .iter()
        .any(|d| matches!(d.reason, Reason::NameMismatch | Reason::HelloUnreadable))
    {
        out.push_str(&format!(
            "{}, {}: the tunnel was allowed, but its TLS hello asked for another server than its host, or could not be read, so the proxy closed it; there is nothing to allow. `enclos net log {sandbox}` shows the name it asked for.\n",
            Reason::NameMismatch,
            Reason::HelloUnreadable
        ));
    }
    if denied.iter().any(|d| d.reason == Reason::PolicyUnreadable) {
        out.push_str(&format!(
            "{}: the proxy could not read the sandbox's policy at those times, so it refused every destination; there is nothing to allow. See why with `enclos logs {sandbox}`.\n",
            Reason::PolicyUnreadable
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_request_is_nothing_to_allow() {
        let shown = denied_text(
            &"home".parse().unwrap(),
            &[refused("plain.example.com", Reason::BadRequest)],
        );
        assert!(!shown.contains("enclos policy allow"), "{shown}");
        assert!(
            shown.contains("bad-request: the request was malformed"),
            "{shown}"
        );
    }

    fn refused(host: &str, reason: Reason) -> DeniedDestination {
        let at = "2026-10-20T12:00:00Z".parse().unwrap();
        DeniedDestination {
            host: host.into(),
            port: 443,
            reason,
            count: 1,
            first: at,
            last: at,
        }
    }

    fn lab() -> SandboxName {
        "lab".parse().unwrap()
    }

    #[test]
    fn a_tunnel_closed_for_its_server_name_is_nothing_to_allow() {
        let text = denied_text(&lab(), &[refused("api.example.com", Reason::NameMismatch)]);
        assert!(
            text.contains("api.example.com:443  name-mismatch"),
            "{text}"
        );
        assert!(!text.contains("policy allow"), "{text}");
        assert!(text.contains("enclos net log lab"), "{text}");
    }

    #[test]
    fn the_log_shows_the_server_name_a_tunnel_asked_for() {
        let event = |seen, name: Option<&str>| NetEvent {
            at: "2026-10-20T12:00:00Z".parse().unwrap(),
            sandbox: lab(),
            host: "api.example.com".into(),
            port: 443,
            method: "CONNECT".into(),
            address: None,
            verdict: Verdict::Allowed,
            reason: None,
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
            name_seen: seen,
            server_name: name.map(str::to_owned),
        };
        for (seen, name, shown) in [
            (
                Some(NameSeen::Name),
                Some("api.example.com"),
                "api.example.com",
            ),
            (Some(NameSeen::NoName), None, "no name seen"),
            (
                Some(NameSeen::Encrypted),
                Some("public.example.net"),
                "hidden (ECH), public name public.example.net",
            ),
            (Some(NameSeen::NotTls), None, "not TLS"),
            (None, None, "-"),
        ] {
            assert_eq!(server_name(&event(seen, name)), shown);
        }
    }

    #[test]
    fn a_refusal_because_the_policy_was_unreadable_is_not_offered_to_allow() {
        let text = denied_text(
            &lab(),
            &[refused("api.example.com", Reason::PolicyUnreadable)],
        );
        assert!(
            text.contains("api.example.com:443  policy-unreadable"),
            "{text}"
        );
        assert!(!text.contains("policy allow"), "{text}");
        assert!(text.contains("nothing to allow"), "{text}");
        assert!(text.contains("`enclos logs lab`"), "{text}");
    }

    #[test]
    fn mixed_refusals_get_both_hints() {
        let text = denied_text(
            &lab(),
            &[
                refused("api.example.com", Reason::PolicyUnreadable),
                refused("evil.example.com", Reason::NotAllowed),
            ],
        );
        assert!(
            text.contains("enclos policy allow lab <destination>"),
            "{text}"
        );
        assert!(text.contains("nothing to allow"), "{text}");
    }

    #[test]
    fn a_plain_refusal_gets_only_the_allow_hint() {
        let text = denied_text(&lab(), &[refused("evil.example.com", Reason::NotAllowed)]);
        assert!(text.contains("enclos policy allow lab"), "{text}");
        assert!(!text.contains("nothing to allow"), "{text}");
    }

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
