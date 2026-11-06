//! `enclos policy show`, `history` and `diff`, in text and in JSON.

use serde_json::{Value, json};

use super::super::output;

use enclos::engine::{PolicyDiff, PolicyHistory, PolicyView};
use enclos::error::{Error, Result};
use enclos::model::policy::{NetMode, PendingPolicy, Policy, PolicyVersion};
use enclos::model::sandbox::SandboxName;

fn version_json(v: &PolicyVersion) -> Value {
    json!({
        "version": v.version,
        "snapshot": v.snapshot.0,
        "by": output::actor(&v.by),
        "at": v.at.to_string(),
        "restores": v.restores,
    })
}

pub(super) fn pending_json(p: &PendingPolicy) -> Value {
    json!({
        "snapshot": p.snapshot.0,
        "by": output::actor(&p.by),
        "at": p.at.to_string(),
        "restores": p.restores,
    })
}

fn policy_json(policy: &enclos::model::policy::Policy) -> Result<Value> {
    serde_json::to_value(policy).map_err(|source| Error::Json {
        what: "the policy",
        source,
    })
}

/// The policy in force, or with `pending` the pending one, field by field.
pub(super) fn show_json(view: &PolicyView, pending: bool) -> Result<Value> {
    let snap = &view.snapshot;
    if pending {
        let Some((p, pending)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: view.sandbox.to_string(),
            });
        };
        return Ok(json!({
            "sandbox": view.sandbox.to_string(),
            "pending": pending_json(p),
            "template": pending.inputs.template.to_string(),
            "active_version": view.version.version,
            "policy": policy_json(&pending.policy)?,
        }));
    }
    Ok(json!({
        "sandbox": view.sandbox.to_string(),
        "version": version_json(&view.version),
        "template": snap.inputs.template.to_string(),
        "file": output::path(&view.file),
        "policy": policy_json(&snap.policy)?,
        "pending": view.pending.as_ref().map(|(p, pending)| {
            let mut shown = pending_json(p);
            shown["changes"] = json!(enclos::engine::policy_differences(&snap.policy, &pending.policy));
            shown
        }),
    }))
}

pub(super) fn history_json(history: &PolicyHistory) -> Value {
    json!({
        "sandbox": history.sandbox.to_string(),
        "active": history.active().map(|a| a.version),
        "versions": history.versions.iter().map(version_json).collect::<Vec<_>>(),
        "pending": history.pending.as_ref().map(pending_json),
    })
}

pub(super) fn print_policy(view: &PolicyView, pending: bool) -> Result<()> {
    let (version, snap) = (&view.version, &view.snapshot);
    if pending {
        let Some((p, pending)) = &view.pending else {
            return Err(Error::NoPendingPolicy {
                sandbox: view.sandbox.to_string(),
            });
        };
        println!(
            "Sandbox {}: pending policy (snapshot {}), template {}, by {}@{} at {}; v{} is in force until `enclos policy apply {}`",
            view.sandbox,
            p.snapshot.short(),
            pending.inputs.template,
            p.by.user,
            p.by.host,
            p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            version.version,
            view.sandbox,
        );
        print_rules(&pending.policy);
        return Ok(());
    }
    println!(
        "Sandbox {}: policy v{} (snapshot {}), template {}, by {}@{} at {}",
        view.sandbox,
        version.version,
        snap.id.short(),
        snap.inputs.template,
        version.by.user,
        version.by.host,
        version.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    );
    print_rules(&snap.policy);
    match &view.pending {
        Some((p, pending)) => {
            println!(
                "\nPending (snapshot {}, by {}@{} at {}): saved while sessions ran under rules it changes, it waits for `enclos policy apply`:",
                p.snapshot.short(),
                p.by.user,
                p.by.host,
                p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            );
            for change in enclos::engine::policy_differences(&snap.policy, &pending.policy) {
                println!("  {change}");
            }
            println!(
                "`enclos policy apply {0}` restarts the sandbox into it; `enclos policy discard {0}` drops it. `enclos policy show {0} --pending` shows it in full.",
                view.sandbox
            );
        }
        None => println!(
            "\nChange it with `enclos policy edit {}` (it edits {}).",
            view.sandbox,
            view.file.display()
        ),
    }
    Ok(())
}

fn print_rules(policy: &Policy) {
    println!("\nFiles (everything else is readable)");
    println!("  writable:   {}", policy.fs.write.join(", "));
    println!(
        "  unreadable: {} paths, and enclos's own files",
        policy.fs.read_deny.len()
    );
    for path in &policy.fs.read_deny {
        println!("    {path}");
    }
    match policy.net.mode {
        NetMode::Public => {
            println!("\nNetwork: public web (every connection is logged)");
            println!("  mode:    public: any public address on ports 80 and 443");
            println!(
                "           never loopback, link-local or metadata addresses, nor private ones unless listed below"
            );
        }
        NetMode::Allowlist => {
            println!("\nNetwork: allowlist (every other destination is denied and logged)");
            println!("  mode:    allowlist: only the destinations below");
        }
    }
    if policy.net.allow.is_empty() {
        println!("  allowed: nothing listed");
    } else {
        println!("  allowed: {}", policy.net.allow.join(", "));
    }
    if !policy.net.private.is_empty() {
        println!(
            "  private addresses allowed for: {}",
            policy.net.private.join(", ")
        );
    }
    if policy.net.listen {
        println!(
            "  listening: allowed on TCP, any port but enclos's proxy ports, on every address: what listens in this sandbox can serve the network"
        );
    }
    let r = &policy.resources;
    // Every field named, so one added is decided on here.
    let enclos::model::policy::Resources {
        open_files: _,
        file_size: _,
        cpu_seconds: _,
        memory: _,
        cpu: _,
    } = r;
    if !r.is_unset() {
        println!(
            "\nLimits (each process, from its start; memory and CPU share for each session as a whole)"
        );
        if let Some(files) = r.open_files {
            println!("  open files: {files}");
        }
        if let Some(seconds) = r.cpu_seconds {
            println!("  CPU time:   {seconds} s");
        }
        if let Some(size) = r.file_size {
            println!("  file size:  {size}");
        }
        if let Some(memory) = &r.memory {
            println!("  memory:     {memory}");
        }
        if let Some(cpu) = &r.cpu {
            println!("  CPU share:  {cpu} cores");
        }
    }
    if !policy.secrets.is_empty() || !policy.agent_secrets.is_empty() {
        // Which secret each variable holds, never its value.
        println!("\nSecrets (values in the secret store, never shown)");
        for (variable, grant) in &policy.secrets {
            println!("  ${variable} = {grant}  (every session and agent)");
        }
        for (agent, grants) in &policy.agent_secrets {
            for (variable, grant) in grants {
                println!("  ${variable} = {grant}  (agent {agent})");
            }
        }
    }
}

pub(super) fn print_history(history: &PolicyHistory) {
    println!("Policy versions of sandbox {}:", history.sandbox);
    let rows: Vec<[String; 5]> = history
        .versions
        .iter()
        .map(|v| {
            let active = history.active().map(|a| a.version);
            let note = match (Some(v.version) == active, v.restores) {
                (true, Some(r)) => format!("in force; restores v{r}"),
                (true, None) => "in force".to_owned(),
                (false, Some(r)) => format!("restores v{r}"),
                (false, None) => String::new(),
            };
            [
                format!("v{}", v.version),
                v.at.strftime("%Y-%m-%d %H:%M:%S").to_string(),
                format!("{}@{}", v.by.user, v.by.host),
                v.snapshot.short().to_owned(),
                note,
            ]
        })
        .collect();
    let header = ["VERSION", "TIME (UTC)", "BY", "SNAPSHOT", ""].map(str::to_owned);
    let mut widths = [0; 4];
    for cells in std::iter::once(&header).chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(cells) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for [version, at, by, snapshot, note] in std::iter::once(&header).chain(&rows) {
        let [w0, w1, w2, w3] = widths;
        let line = format!("  {version:<w0$}  {at:<w1$}  {by:<w2$}  {snapshot:<w3$}  {note}");
        println!("{}", line.trim_end());
    }
    if let Some(p) = &history.pending {
        let restores = p
            .restores
            .map(|r| format!(", restoring v{r}"))
            .unwrap_or_default();
        println!(
            "Pending: snapshot {}, by {}@{} at {}{restores}; `enclos policy apply {}` restarts the sandbox into it.",
            p.snapshot.short(),
            p.by.user,
            p.by.host,
            p.at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            history.sandbox
        );
    }
}

pub(super) fn print_diff(sandbox: &SandboxName, diff: &PolicyDiff) {
    if diff.changes.is_empty() && diff.inputs.is_empty() {
        println!(
            "Sandbox {sandbox}: {} grants the same as v{}.",
            diff.to, diff.from
        );
        return;
    }
    println!(
        "Sandbox {sandbox}: what {} changes from v{}:",
        diff.to, diff.from
    );
    if diff.changes.is_empty() {
        println!("  it grants the same");
    }
    for change in &diff.changes {
        println!("  {change}");
    }
    for input in &diff.inputs {
        println!("  {input}");
    }
}
