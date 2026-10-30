//! The Seatbelt probe list as it was before the probes were split per
//! backend (M3-06), so that the split is seen to change none of it. Every
//! probe, in order, on each baseline; regenerate only for a change meant to
//! show in `policy test`.

use std::path::Path;

use crate::probes::{
    Expect, HOST_SERVICE_ROUTES, HostCheck, KeychainItem, NOT_PROBED, Probe, ProbeInputs, Proof,
    host_service_probes, not_here, probes,
};

use super::Baseline;

const EXPECTED: &str = include_str!("probes.snapshot");

/// A host that has something for every probe to find, under `dir`.
fn inputs(dir: &Path, baseline: Baseline, listen: bool) -> ProbeInputs {
    let user = dir.join("user");
    let data = user.join(".enclos");
    let sandbox = data.join("sandboxes/home");
    let work = user.join("work");
    for folder in [
        data.join("run"),
        sandbox.join("home/tmp"),
        sandbox.join("compiled"),
        data.join("sandboxes/lab/home"),
        work.join(".secrets"),
        user.join(".ssh"),
        user.join("Library/Keychains"),
        user.join("Library/LaunchAgents"),
    ] {
        std::fs::create_dir_all(folder).unwrap();
    }
    for file in [
        data.join("state.db"),
        data.join("state.lock"),
        data.join("audit.jsonl"),
        data.join("config.toml"),
        work.join(".env"),
        user.join("Library/Keychains/login.keychain-db"),
    ] {
        std::fs::write(file, "").unwrap();
    }
    if listen {
        std::fs::write(sandbox.join("policy.toml"), "").unwrap();
    }
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(work.join("pipe"))
        .status()
        .unwrap();
    assert!(made.success());
    ProbeInputs {
        user_home: user.clone(),
        data: data.clone(),
        config_file: data.join("config.toml"),
        sandbox_dir: sandbox.clone(),
        other_sandboxes: vec![data.join("sandboxes/lab")],
        writes: vec![sandbox.join("home"), work.clone()],
        read_deny: vec![
            user.join(".ssh"),
            work.join(".secrets"),
            work.join(".env"),
            work.join("pipe"),
            user.join("absent"),
        ],
        home: sandbox.join("home"),
        workspaces: vec![work.clone(), user.join("not-made-yet")],
        unmovable: vec![
            sandbox.join("home"),
            work.clone(),
            user.join("not-a-folder"),
        ],
        host_sockets: vec![user.join("agent.sock")],
        proxy_port: 41001,
        listen,
        baseline,
        target: Some(4242),
        other_terminal: Some("/dev/ttys042".into()),
        tag: 7,
        keychain_item: Ok(KeychainItem {
            service: "enclos.abc.probe".into(),
            account: "home/probe".into(),
            file: Some(user.join("probe.keychain-db")),
        }),
        limits: crate::backend::LaunchLimits::of_checked(&crate::model::policy::Resources {
            open_files: Some(256),
            ..Default::default()
        })
        .unwrap(),
    }
}

fn expect(expect: &Expect) -> String {
    match expect {
        Expect::Fails => "fails".to_owned(),
        Expect::FailsWith(text) => format!("fails with {text}"),
        Expect::OutputLacks(text) => format!("output lacks {text}"),
        Expect::IntoItself => "into itself".to_owned(),
        Expect::AppleEventBlocked(text) => format!("apple event blocked: {text}"),
    }
}

fn proof(proof: &Proof) -> String {
    match proof {
        Proof::Control { expect: e, control } => {
            format!("{}\n  control: {}", expect(e), control.as_str())
        }
        Proof::ProxyRefuses => "the proxy refuses".to_owned(),
        Proof::OnlyTheProxy { control } => {
            format!("only the proxy\n  control: {}", control.as_str())
        }
    }
}

fn host(check: &HostCheck) -> String {
    match check {
        HostCheck::File(path) => format!("the file {}", path.display()),
        HostCheck::LaunchdJob(label) => format!("the launchd job {label}"),
        HostCheck::PreferencesDomain(d) => format!("the preferences domain {d}"),
        HostCheck::Target => "the signal probe's target".to_owned(),
    }
}

fn render(probe: &Probe) -> String {
    let mut text = format!(
        "{} | {}\n  script: {}\n  proof: {}\n",
        probe.route,
        probe.name,
        probe.script,
        proof(&probe.proof)
    );
    if let Some(check) = &probe.host {
        text.push_str(&format!("  host: {}\n", host(check)));
    }
    if let Some(by) = probe.closed_by {
        text.push_str(&format!("  closed by: {}: {}\n", by.key(), by.why()));
    }
    text
}

fn snapshot() -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for (name, baseline, listen) in [
        ("deny default", Baseline::DenyDefault, false),
        ("allow default, listening", Baseline::AllowDefault, true),
    ] {
        let at = dir.path().join(name.replace([' ', ','], "-"));
        let i = inputs(&at, baseline, listen);
        text.push_str(&format!("## {name}\n"));
        for p in probes(&i) {
            text.push_str(&render(&p));
        }
        text.push_str("### host services\n");
        for p in host_service_probes(&i) {
            text.push_str(&render(&p));
        }
        text.push_str("### not here\n");
        for line in not_here(&i) {
            text.push_str(&format!("{line}\n"));
        }
        text = text.replace(&at.display().to_string(), "<dir>");
    }
    text.push_str("## host-service routes\n");
    text.push_str(&format!("{}\n", HOST_SERVICE_ROUTES.join("\n")));
    text.push_str("## not probed\n");
    text.push_str(&format!("{}\n", NOT_PROBED.join("\n")));
    text
}

#[test]
fn the_seatbelt_probe_list_is_as_it_was() {
    let got = snapshot();
    if std::env::var_os("ENCLOS_WRITE_SNAPSHOTS").is_some() {
        let file =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backend/seatbelt/probes.snapshot");
        std::fs::write(file, &got).unwrap();
        return;
    }
    let (got, expected): (Vec<_>, Vec<_>) = (got.lines().collect(), EXPECTED.lines().collect());
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}
