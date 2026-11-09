//! `enclos status` and what it suggests (design §9).

use std::path::Path;

use super::policy::with_sandbox_on;
use super::*;
use crate::engine::status::suggest;
use crate::engine::{AgentKind, AgentList, AgentStatus, Fact, Presence, SandboxStatus};
use crate::model::Timestamp;
use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::runtime::{
    AgentFacts, HomeFile, HomePath, Installer, NotRead, RuntimeAdapter, RuntimeAgentName,
    RuntimeFacts, SandboxCommand, Unreadable, ValueAt,
};

/// A runtime adapter that implements none of the `status` methods.
struct Bare;

impl RuntimeAdapter for Bare {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Hermes
    }
    fn version(&self) -> &'static str {
        "0"
    }
    fn endpoints(&self) -> &'static str {
        ""
    }
    fn installer(&self) -> Installer {
        Installer {
            url: String::new(),
            args: Vec::new(),
        }
    }
    fn home_files(&self, _: crate::model::sandbox::BackendKind) -> Vec<HomeFile> {
        Vec::new()
    }
    fn login(&self) -> String {
        String::new()
    }
    fn create_agent(&self, _: &AgentName) -> SandboxCommand {
        SandboxCommand::from_words(&[])
    }
    fn agent_files(&self, _: &AgentName) -> String {
        String::new()
    }
    fn talk(&self, _: &AgentName) -> String {
        String::new()
    }
    fn services(&self) -> Vec<crate::runtime::RuntimeService> {
        Vec::new()
    }
    fn agents_in(&self, _: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
        Ok(Vec::new())
    }
}

/// A second native representation: shared JSON with JSON-pointer selectors
/// and a configured removable default, without an immutable built-in agent.
struct JsonRuntime;

fn json_file() -> HomePath {
    HomePath::new("runtime.json").unwrap()
}

impl RuntimeAdapter for JsonRuntime {
    fn kind(&self) -> RuntimeKind {
        Bare.kind()
    }
    fn version(&self) -> &'static str {
        "0"
    }
    fn endpoints(&self) -> &'static str {
        ""
    }
    fn installer(&self) -> Installer {
        Bare.installer()
    }
    fn home_files(&self, backend: BackendKind) -> Vec<HomeFile> {
        Bare.home_files(backend)
    }
    fn login(&self) -> String {
        String::new()
    }
    fn create_agent(&self, name: &AgentName) -> SandboxCommand {
        Bare.create_agent(name)
    }
    fn agent_files(&self, _: &AgentName) -> String {
        String::new()
    }
    fn talk(&self, _: &AgentName) -> String {
        String::new()
    }
    fn services(&self) -> Vec<crate::runtime::RuntimeService> {
        Vec::new()
    }
    fn agents_in(&self, home: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
        Ok(self.default_agent(home)?.into_iter().collect())
    }
    fn default_agent(
        &self,
        home: &Path,
    ) -> std::result::Result<Option<RuntimeAgentName>, Unreadable> {
        let Some(text) = crate::runtime::home::read_text(home, &json_file(), 256 * 1024)? else {
            return Ok(None);
        };
        let at = ValueAt {
            file: json_file(),
            keys: vec!["/selected".into()],
        };
        let invalid = || Unreadable {
            path: json_file().to_string(),
            why: NotRead::Io("invalid runtime selection".into()),
        };
        self.fact_value(&at, &text)
            .map_err(|_| invalid())?
            .map(|name| RuntimeAgentName::new(&name).ok_or_else(invalid))
            .transpose()
    }
    fn fact_value(&self, at: &ValueAt, text: &str) -> std::result::Result<Option<String>, String> {
        let doc: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "invalid runtime JSON".to_owned())?;
        for key in &at.keys {
            if let Some(value) = doc.pointer(key) {
                return value
                    .as_str()
                    .map(|s| Some(s.to_owned()))
                    .ok_or_else(|| "runtime fact is not text".into());
            }
        }
        Ok(None)
    }
    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts {
            version: Some(ValueAt {
                file: json_file(),
                keys: vec!["/version".into()],
            }),
            ..RuntimeFacts::default()
        }
    }
    fn agent_facts(&self, agent: &RuntimeAgentName) -> AgentFacts {
        AgentFacts {
            model: Some(ValueAt {
                file: json_file(),
                keys: vec![format!("/models/{agent}")],
            }),
            ..AgentFacts::default()
        }
    }
}

#[test]
fn shared_json_facts_and_removable_defaults_cross_the_same_runtime_interface() {
    let (_dir, engine, name) = with_runtime();
    let home = engine.sandbox_home(&name);
    let file = home.join("runtime.json");
    let status = || {
        let record = engine.state.get(&name).unwrap().unwrap();
        let created = record.created_at;
        engine
            .sandbox_status(record, Some(&JsonRuntime), created)
            .unwrap()
    };
    assert_eq!(JsonRuntime.builtin_agent(), None);
    assert_eq!(JsonRuntime.default_agent(&home).unwrap(), None);
    assert_eq!(Bare.default_agent(&home).unwrap(), None);
    assert_eq!(status().runtime.unwrap().version, Fact::Absent);
    assert_eq!(status().agents.unwrap().agents, Vec::new());

    std::fs::write(
        &file,
        r#"{"selected":"main","version":"1","models":{"main":"model\u001b[2J"}}"#,
    )
    .unwrap();
    let view = status();
    let runtime = view.runtime.unwrap();
    assert_eq!(runtime.version, Fact::Known("1".into()));
    assert_eq!(runtime.logged_in, Fact::NotProvided);
    let agents = view.agents.unwrap().agents;
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name.as_str(), "main");
    assert_eq!(agents[0].kind, AgentKind::Untracked);
    assert_eq!(agents[0].model, Fact::Known("model\\u{1b}[2J".into()));

    // A different configured default replaces main, which is not invented
    // again as a built-in agent. A missing fact remains absent.
    std::fs::write(&file, r#"{"selected":"scout","version":"2"}"#).unwrap();
    assert_eq!(
        JsonRuntime.default_agent(&home).unwrap().unwrap().as_str(),
        "scout"
    );
    let view = status();
    let agents = view.agents.unwrap().agents;
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name.as_str(), "scout");
    assert_eq!(agents[0].model, Fact::Absent);

    std::fs::write(&file, "{broken").unwrap();
    assert_eq!(
        status().runtime.unwrap().version,
        Fact::CannotTell("~/runtime.json: invalid runtime JSON".into())
    );
    assert!(JsonRuntime.default_agent(&home).is_err());

    std::fs::remove_file(&file).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("runtime.json"),
        r#"{"selected":"host"}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path().join("runtime.json"), &file).unwrap();
    assert_eq!(
        status().runtime.unwrap().version,
        Fact::CannotTell("~/runtime.json is a link".into())
    );
    assert!(JsonRuntime.default_agent(&home).is_err());
}

#[test]
fn an_omitted_agent_uses_the_installed_runtime_target() {
    let (_dir, engine, name) = with_runtime();
    assert_eq!(
        engine.default_agent(&name).unwrap().unwrap().as_str(),
        "default"
    );
    let missing = "missing".parse().unwrap();
    assert!(engine.default_agent(&missing).is_err());
    let (_dir, bare, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    assert!(
        bare.default_agent(&name)
            .unwrap_err()
            .to_string()
            .contains("no runtime")
    );
}

fn with_runtime() -> (TempDir, Engine, SandboxName) {
    let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                engine.state.put(lock, &record)?;
                Ok(())
            },
        )
        .unwrap();
    (dir, engine, name)
}

fn days(n: i64) -> jiff::SignedDuration {
    jiff::SignedDuration::from_hours(24 * n)
}

fn commands(s: &[Suggestion]) -> Vec<String> {
    s.iter().map(Suggestion::command).collect()
}

#[test]
fn a_runtime_that_names_nothing_gets_sizes_no_agents_and_suggestions() {
    let (_dir, engine, name) = with_runtime();
    std::fs::write(engine.sandbox_home(&name).join("data"), vec![b'x'; 300_000]).unwrap();
    let record = engine.state.get(&name).unwrap().unwrap();
    let created = record.created_at;
    let status = engine.sandbox_status(record, Some(&Bare), created).unwrap();
    assert_eq!(status.disk.incomplete, None);
    assert!(status.disk.total >= 300_000);
    assert_eq!(status.disk.other, status.disk.total);
    assert_eq!(
        (status.disk.runtime, status.disk.caches, status.disk.agents),
        (None, None, None)
    );
    // A runtime that lists none: no agents, which is not "cannot tell".
    assert_eq!(
        status.agents,
        Some(AgentList {
            agents: Vec::new(),
            unreadable: None
        })
    );
    let rt = status.runtime.as_ref().unwrap();
    assert_eq!(
        (&rt.version, &rt.logged_in, &rt.installed),
        (&Fact::NotProvided, &Fact::NotProvided, &Fact::NotProvided)
    );
    assert_eq!(
        commands(&suggest(std::slice::from_ref(&status), created)),
        ["enclos agent add home/main"]
    );

    // Unused for 30 days, exactly, it is worth removing; a second less,
    // not yet.
    let at = |d| created.checked_add(d).unwrap();
    let almost = at(days(30) - jiff::SignedDuration::from_secs(1));
    assert_eq!(suggest(std::slice::from_ref(&status), almost).len(), 1);
    let s = suggest(std::slice::from_ref(&status), at(days(30)));
    assert_eq!(
        commands(&s),
        ["enclos agent add home/main", "enclos sandbox rm home"]
    );
    assert!(
        s[1].reason()
            .starts_with("unused for 30 days; removing it frees ")
    );
    assert!(!s[1].reason().contains('≥'), "{}", s[1].reason());
}

#[test]
fn hermes_agents_logins_and_models_show_with_what_to_do() {
    let (_dir, engine, name) = with_runtime();
    let home = engine.sandbox_home(&name);
    let scout = home.join(".hermes/profiles/scout");
    std::fs::create_dir_all(&scout).unwrap();
    std::fs::write(
        scout.join("config.yaml"),
        "model:\n  default: gpt-6.1-sol\n",
    )
    .unwrap();
    std::fs::write(scout.join(".hermes_history"), "hello").unwrap();
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    std::fs::write(home.join(".hermes/hermes-agent/big"), vec![b'x'; 200_000]).unwrap();
    // Hermes's own `default` profile, at the root of its home.
    std::fs::write(
        home.join(".hermes/config.yaml"),
        "model:\n  model: gpt-6.1-terra\n",
    )
    .unwrap();
    std::fs::write(home.join(".hermes/state.db"), vec![b'x'; 50_000]).unwrap();

    let view = engine.status(None).unwrap();
    let s = &view.sandboxes[0];
    let rt = s.runtime.as_ref().unwrap();
    assert_eq!(
        (&rt.logged_in, &rt.installed),
        (&Fact::Known(false), &Fact::Known(true))
    );
    let list = s.agents.as_ref().unwrap();
    assert_eq!(list.unreadable, None);
    assert_eq!(list.agents.len(), 2);
    let d = &list.agents[0];
    assert_eq!(
        (d.name.as_str(), d.kind, &d.model),
        (
            "default",
            AgentKind::Builtin,
            &Fact::Known("gpt-6.1-terra".into())
        )
    );
    // Its size is the root data, not the runtime install under it.
    let size = *d.bytes.known().unwrap();
    assert!((50_000..200_000).contains(&size), "{size}");
    assert!(d.last_active.known().is_some());
    let a = &list.agents[1];
    assert_eq!(
        (a.name.as_str(), a.kind, &a.model),
        (
            "scout",
            AgentKind::Untracked,
            &Fact::Known("gpt-6.1-sol".into())
        )
    );
    assert!(a.last_active.known().is_some() && *a.bytes.known().unwrap() > 0);
    assert!(s.disk.runtime.unwrap() >= 200_000);
    assert_eq!(
        commands(&view.suggestions),
        [
            "enclos agent add home/scout",
            "enclos connect home -- hermes -p default setup"
        ]
    );
    assert_eq!((view.agent_count(), view.untracked_count()), (1, 1));
    assert_eq!(engine.status(Some(&name)).unwrap().sandboxes.len(), 1);
    let err = engine.status(Some(&"nope".parse().unwrap())).unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");

    // Logged in, the suggestion goes.
    std::fs::write(home.join(".hermes/auth.json"), "{}").unwrap();
    let view = engine.status(None).unwrap();
    assert_eq!(
        view.sandboxes[0].runtime.as_ref().unwrap().logged_in,
        Fact::Known(true)
    );
    assert_eq!(commands(&view.suggestions), ["enclos agent add home/scout"]);
}

#[test]
fn an_agent_whose_settings_name_no_provider_is_said_with_how_to_choose_one() {
    let (_dir, engine, name) = with_runtime();
    let home = engine.sandbox_home(&name);
    // Added before the sandbox's login chose a provider, as Hermes 0.23.0
    // clones `default`'s settings: `auto`, kept after the login.
    let main = home.join(".hermes/profiles/main");
    std::fs::create_dir_all(&main).unwrap();
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    std::fs::write(
        main.join("config.yaml"),
        "model:\n  default: gpt-5.5\n  provider: auto\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".hermes/config.yaml"),
        "model:\n  default: gpt-5.5\n  provider: openai-codex\n",
    )
    .unwrap();
    let added = done(
        engine
            .add_agent(&alice(), &name, "main".parse().unwrap(), Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(
        added.choose_provider.as_deref(),
        Some("hermes -p main model")
    );

    let agents = |view: &crate::engine::StatusView| {
        view.sandboxes[0].agents.as_ref().unwrap().agents.clone()
    };
    let view = engine.status(None).unwrap();
    let [default, tracked] = &agents(&view)[..] else {
        panic!("{:?}", agents(&view));
    };
    assert_eq!(
        (&default.provider, &default.choose_provider),
        (&Fact::Known("openai-codex".into()), &None)
    );
    assert_eq!(
        (&tracked.provider, tracked.choose_provider.as_deref()),
        (&Fact::Known("auto".into()), Some("hermes -p main model"))
    );
    // Not logged in yet: the login comes first, and chooses a provider.
    assert_eq!(
        commands(&view.suggestions),
        ["enclos connect home -- hermes -p default setup"]
    );
    std::fs::write(home.join(".hermes/auth.json"), "{}").unwrap();
    let view = engine.status(None).unwrap();
    let suggested = &view.suggestions[0];
    assert_eq!(
        (suggested.kind(), suggested.target(), suggested.command()),
        (
            "choose_provider",
            "home/main".to_owned(),
            "enclos connect home -- hermes -p main model".to_owned()
        )
    );
    assert_eq!(view.suggestions.len(), 1);
    let json = serde_json::to_value(&view).unwrap();
    let shown = &json["sandboxes"][0]["agents"]["agents"][1];
    assert_eq!(shown["provider"], serde_json::json!({"known": "auto"}));
    assert_eq!(shown["choose_provider"], "hermes -p main model");

    // Chosen, nothing is said.
    std::fs::write(
        main.join("config.yaml"),
        "model:\n  default: gpt-5.5\n  provider: openai-codex\n",
    )
    .unwrap();
    let view = engine.status(None).unwrap();
    assert_eq!(agents(&view)[1].choose_provider, None);
    assert!(view.suggestions.is_empty(), "{:?}", view.suggestions);
}

#[test]
fn enclos_neither_adds_nor_removes_the_built_in_agent() {
    let (_dir, engine, name) = with_runtime();
    let default: AgentName = "default".parse().unwrap();
    let audited = engine.audit(None).unwrap().len();
    let err = engine
        .add_agent(&alice(), &name, default.clone(), Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("is Hermes's built-in agent")
            && err
                .to_string()
                .contains("enclos connect home -- hermes -p default`"),
        "{err}"
    );
    let err = engine
        .remove_agent(&alice(), &name, &default, false, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string().contains("is Hermes's built-in agent"),
        "{err}"
    );
    assert!(engine.agents(&name).unwrap().is_empty());
    assert_eq!(engine.audit(None).unwrap().len(), audited);
    assert_eq!(
        engine.builtin_agent(&name).unwrap().map(|b| b.as_str()),
        Some("default")
    );
}

#[test]
fn an_unreadable_agent_list_is_said_and_nothing_is_called_gone() {
    let (_dir, engine, name) = with_runtime();
    let home = engine.sandbox_home(&name);
    std::fs::create_dir_all(home.join(".hermes/profiles/scout")).unwrap();
    std::fs::write(home.join(".hermes/profiles/scout/config.yaml"), "").unwrap();
    done(
        engine
            .add_agent(&alice(), &name, "scout".parse().unwrap(), Confirm::Yes)
            .unwrap(),
    );
    std::fs::rename(home.join(".hermes"), home.join("kept")).unwrap();
    std::os::unix::fs::symlink(home.join("kept"), home.join(".hermes")).unwrap();
    let view = engine.status(None).unwrap();
    let list = view.sandboxes[0].agents.as_ref().unwrap();
    assert_eq!(list.unreadable.as_deref(), Some("~/.hermes is a link"));
    let kinds: Vec<(&str, AgentKind)> = list
        .agents
        .iter()
        .map(|a| (a.name.as_str(), a.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("default", AgentKind::Builtin),
            (
                "scout",
                AgentKind::Tracked {
                    in_runtime: Presence::Unknown
                }
            )
        ]
    );
    // Facts behind the link are not read either.
    assert!(matches!(&list.agents[1].model, Fact::CannotTell(why) if why.contains("link")));
    let rt = view.sandboxes[0].runtime.as_ref().unwrap();
    assert_eq!(rt.logged_in, Fact::CannotTell("~/.hermes is a link".into()));
    let s = &view.suggestions;
    assert_eq!(commands(s), ["enclos connect home"]);
    assert_eq!(
        s[0].reason(),
        "enclos cannot read Hermes's agents: ~/.hermes is a link"
    );
}

#[test]
fn missing_runtime_files_suggest_installing_again_rather_than_logging_in() {
    let (_dir, engine, name) = with_runtime();
    std::fs::create_dir_all(engine.sandbox_home(&name).join(".hermes")).unwrap();
    let view = engine.status(None).unwrap();
    let rt = view.sandboxes[0].runtime.as_ref().unwrap();
    assert_eq!(rt.installed, Fact::Known(false));
    assert_eq!(
        commands(&view.suggestions),
        ["enclos runtime install hermes --sandbox home"]
    );
    assert_eq!(
        view.suggestions[0].reason(),
        "Hermes's files are missing from the home"
    );
}

/// A session of `kind`, started at `start`, ended at `end`.
fn put_session(
    engine: &Engine,
    name: &SandboxName,
    kind: SessionKind,
    compiled: Option<&str>,
    start: Timestamp,
    end: Option<Timestamp>,
) {
    let session = SessionRecord {
        id: SessionId(0),
        sandbox: name.clone(),
        kind,
        service: (kind == SessionKind::Service).then(|| "gateway".to_owned()),
        version: 1,
        snapshot: engine.policy(name).unwrap().snapshot.id,
        compiled: compiled.map(str::to_owned),
        root: crate::lifecycle::process::reference(std::process::id())
            .unwrap()
            .unwrap(),
        pgid: None,
        cgroup: None,
        tracked: Vec::new(),
        started_at: start,
        ended_at: end,
    };
    let lock = engine.state.lock().unwrap();
    engine.state.put_session(&lock, &session).unwrap();
}

fn net_event(name: &SandboxName, at: Timestamp, denied: bool) -> crate::model::net::NetEvent {
    use crate::model::net::{NetEvent, Reason, Verdict};
    NetEvent {
        at,
        sandbox: name.clone(),
        host: "example.com".into(),
        port: 443,
        method: "CONNECT".into(),
        address: None,
        verdict: if denied {
            Verdict::Denied
        } else {
            Verdict::Allowed
        },
        reason: denied.then_some(Reason::NotAllowed),
        bytes_up: 0,
        bytes_down: 0,
        duration_ms: 0,
        name_seen: None,
    }
}

#[test]
fn the_last_use_counts_connect_and_service_sessions_and_the_network_not_the_proxy() {
    use crate::engine::status::last_used;
    let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
    let at = |d: i64| t0.checked_add(days(d)).unwrap();
    let session = |kind, start, end| SessionRecord {
        id: SessionId(0),
        sandbox: "home".parse().unwrap(),
        kind,
        service: None,
        version: 1,
        snapshot: crate::model::policy::SnapshotId("x".into()),
        compiled: None,
        root: crate::lifecycle::process::reference(std::process::id())
            .unwrap()
            .unwrap(),
        pgid: None,
        cgroup: None,
        tracked: Vec::new(),
        started_at: start,
        ended_at: end,
    };
    assert_eq!(last_used(t0, &[], None), t0);
    // A `connect` from day 1 to day 5, a service that ended on day 9, a
    // proxy that ran until day 20, and a connection tried on day 7.
    let sessions = [
        session(SessionKind::Interactive, at(1), Some(at(5))),
        session(SessionKind::Service, at(2), Some(at(9))),
        session(SessionKind::Proxy, at(3), Some(at(20))),
    ];
    assert_eq!(last_used(t0, &sessions, Some(at(7))), at(9));
    assert_eq!(last_used(t0, &sessions[2..], Some(at(7))), at(7));
    assert_eq!(last_used(t0, &sessions[..1], None), at(5));
}

#[test]
fn sessions_and_the_network_log_give_last_connect_and_what_needs_a_restart() {
    let (_dir, engine, name) = with_runtime();
    let record = engine.state.get(&name).unwrap().unwrap();
    let t0 = record.created_at;
    let fresh = engine
        .sandbox_status(record.clone(), Some(&Bare), t0)
        .unwrap();
    assert_eq!(
        (fresh.last_connect, fresh.last_network, fresh.last_used),
        (None, None, t0)
    );
    assert!(!fresh.restart_needed && fresh.running_sessions == 0);
    assert!(!fresh.in_use());

    let later = t0.checked_add(jiff::SignedDuration::from_secs(60)).unwrap();
    put_session(&engine, &name, SessionKind::Interactive, None, later, None);
    engine
        .state
        .record(&net_event(&name, later, false))
        .unwrap();
    let status = engine
        .sandbox_status(record.clone(), Some(&Bare), later)
        .unwrap();
    assert_eq!(
        (status.last_connect, status.last_network, status.last_used),
        (Some(later), Some(later), later)
    );
    assert_eq!(status.running_sessions, 1);
    assert!(status.in_use());
    // A session without a compiled file, as the proxy runs, applies
    // network rules live: no restart. One on a compiled file the active
    // policy replaced needs one.
    assert!(!status.restart_needed);
    put_session(
        &engine,
        &name,
        SessionKind::Interactive,
        Some("/old/compiled.sb"),
        later,
        None,
    );
    let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
    assert!(status.restart_needed);
    assert!(commands(&suggest(&[status], later)).contains(&"enclos sandbox restart home".into()));
}

#[test]
fn a_sandbox_that_cannot_be_read_is_listed_with_why_and_the_total_is_a_lower_bound() {
    let (_dir, engine, name) = with_runtime();
    let spec = crate::engine::SandboxSpec {
        name: "spare".parse().unwrap(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    assert!(engine.status(None).unwrap().complete);
    put_session(
        &engine,
        &name,
        SessionKind::Interactive,
        None,
        crate::model::now(),
        None,
    );
    let db = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
    db.execute("UPDATE sessions SET started_at = 'not a time'", [])
        .unwrap();
    let view = engine.status(None).unwrap();
    let listed: Vec<&str> = view.sandboxes.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(listed, ["spare"]);
    assert_eq!(view.unlisted.len(), 1);
    assert_eq!(view.unlisted[0].name, name);
    assert!(!view.unlisted[0].error.is_empty());
    // Its folder is not in `bytes`, so the total is a lower bound.
    assert!(!view.complete);
}

#[test]
fn refused_destinations_count_for_seven_days_exactly() {
    let (_dir, engine, name) = with_runtime();
    let record = engine.state.get(&name).unwrap().unwrap();
    let now = record.created_at.checked_add(days(20)).unwrap();
    let week = now.checked_sub(days(7)).unwrap();
    engine.state.record(&net_event(&name, week, true)).unwrap();
    let status = engine
        .sandbox_status(record.clone(), Some(&Bare), now)
        .unwrap();
    assert_eq!(status.refused_recently, 1);
    let s = suggest(std::slice::from_ref(&status), now);
    assert!(
        commands(&s).contains(&"enclos net denied home".into()),
        "{s:?}"
    );
    let later = now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap();
    let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
    assert_eq!(status.refused_recently, 0);
}

#[test]
fn a_refusal_because_the_policy_was_unreadable_is_not_a_destination_to_review() {
    use crate::model::net::Reason;
    let (_dir, engine, name) = with_runtime();
    let record = engine.state.get(&name).unwrap().unwrap();
    let now = record.created_at.checked_add(days(1)).unwrap();
    let mut event = net_event(&name, now, true);
    event.reason = Some(Reason::PolicyUnreadable);
    engine.state.record(&event).unwrap();
    // `net denied` still lists it, with its reason.
    let denied = engine.net_denied(&name).unwrap();
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].reason, Reason::PolicyUnreadable);
    let status = engine
        .sandbox_status(record.clone(), Some(&Bare), now)
        .unwrap();
    assert_eq!(status.refused_recently, 0);
    assert_eq!(status.policy_unreadable_at, Some(now));
    assert_eq!(status.policy_unreadable_refused, 1);
    // Not a destination to review, but a proxy to look at.
    let s = suggest(std::slice::from_ref(&status), now);
    let listed = commands(&s);
    // What was refused, not every connection.
    let reasons: Vec<String> = s.iter().map(Suggestion::reason).collect();
    assert!(
        reasons.contains(&format!(
            "1 connection refused as the proxy could not read the policy, the last at {}",
            now.strftime("%Y-%m-%d %H:%M UTC")
        )),
        "{reasons:?}"
    );
    assert!(!listed.contains(&"enclos net denied home".into()), "{s:?}");
    assert!(listed.contains(&"enclos logs home".into()), "{s:?}");

    // A real refusal beside it is still one to review.
    let mut other = net_event(&name, now, true);
    other.host = "evil.example.com".into();
    engine.state.record(&other).unwrap();
    let status = engine
        .sandbox_status(record.clone(), Some(&Bare), now)
        .unwrap();
    assert_eq!(status.refused_recently, 1);
    let listed = commands(&suggest(std::slice::from_ref(&status), now));
    assert!(
        listed.contains(&"enclos net denied home".into()),
        "{listed:?}"
    );
    assert!(listed.contains(&"enclos logs home".into()), "{listed:?}");

    // After 7 days, neither is suggested.
    let later = now.checked_add(days(8)).unwrap();
    let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
    assert_eq!(status.policy_unreadable_at, None);
    assert_eq!(status.refused_recently, 0);
}

#[test]
fn each_rule_names_its_command_and_nothing_fires_without_its_fact() {
    let (_dir, engine, name) = with_runtime();
    let record = engine.state.get(&name).unwrap().unwrap();
    let t0 = record.created_at;
    let base = engine.sandbox_status(record, Some(&Bare), t0).unwrap();
    let with_agents = |agents: Vec<(&str, AgentKind)>| SandboxStatus {
        agents: Some(AgentList {
            agents: agents
                .into_iter()
                .map(|(n, kind)| AgentStatus {
                    name: crate::runtime::RuntimeAgentName::new(n).unwrap(),
                    kind,
                    last_active: Fact::NotProvided,
                    bytes: Fact::NotProvided,
                    model: Fact::NotProvided,
                    provider: Fact::NotProvided,
                    choose_provider: None,
                })
                .collect(),
            unreadable: None,
        }),
        ..base.clone()
    };
    let s = with_agents(vec![
        ("default", AgentKind::Builtin),
        (
            "main",
            AgentKind::Tracked {
                in_runtime: Presence::Present,
            },
        ),
        (
            "gone",
            AgentKind::Tracked {
                in_runtime: Presence::Gone,
            },
        ),
        (
            "lost",
            AgentKind::Tracked {
                in_runtime: Presence::Unknown,
            },
        ),
        ("scout", AgentKind::Untracked),
        ("my_bot", AgentKind::Untrackable),
    ]);
    // The two counts split every agent of every sandbox.
    let other = with_agents(vec![("bot", AgentKind::Untracked)]);
    let mut view = engine.status(None).unwrap();
    view.sandboxes = vec![s.clone(), other];
    assert_eq!((view.agent_count(), view.untracked_count()), (4, 3));
    assert_eq!(
        commands(&suggest(&[s], t0)),
        ["enclos agent rm home/gone", "enclos agent add home/scout"]
    );
    let none = SandboxStatus {
        runtime: None,
        agents: None,
        ..base.clone()
    };
    assert_eq!(
        commands(&suggest(&[none], t0)),
        ["enclos runtime install <runtime> --sandbox home"]
    );

    // Something running, or a service manager that cannot say, keeps an
    // old sandbox from being called unused.
    let old = t0.checked_add(days(40)).unwrap();
    let idle = with_agents(vec![("default", AgentKind::Builtin)]);
    assert_eq!(
        commands(&suggest(std::slice::from_ref(&idle), old)),
        ["enclos sandbox rm home"]
    );
    let running = SandboxStatus {
        running_sessions: 1,
        ..idle.clone()
    };
    let unknown = SandboxStatus {
        services: Fact::CannotTell("no GUI domain".into()),
        ..idle.clone()
    };
    let service = SandboxStatus {
        services: Fact::Known(vec![crate::engine::ServiceLine {
            label: "enclos.x.home.gateway".into(),
            service: "gateway".into(),
            state: crate::engine::ServiceState::Running { pid: 1 },
        }]),
        ..idle.clone()
    };
    for busy in [running, unknown, service] {
        assert!(suggest(&[busy], old).is_empty());
    }
    // A walk that stopped early says the size is a lower bound.
    let partial = SandboxStatus {
        disk: crate::engine::Disk {
            incomplete: Some("stopped after 1000000 entries".into()),
            ..idle.disk.clone()
        },
        ..idle
    };
    let s = suggest(&[partial], old);
    assert!(s[0].reason().contains("frees ≥ "), "{}", s[0].reason());
}

#[test]
fn the_json_view_names_each_state_and_fact() {
    let (_dir, engine, name) = with_runtime();
    let home = engine.sandbox_home(&name);
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    let json = serde_json::to_value(engine.status(None).unwrap()).unwrap();
    let s = &json["sandboxes"][0];
    assert_eq!(s["name"], "home");
    assert_eq!(s["state"], "created");
    assert_eq!(s["services"], serde_json::json!({"known": []}));
    assert_eq!(s["runtime"]["kind"], "hermes");
    assert_eq!(s["runtime"]["version"], "not_provided");
    assert_eq!(
        s["runtime"]["logged_in"],
        serde_json::json!({"known": false})
    );
    let default = &s["agents"]["agents"][0];
    assert_eq!(default["name"], "default");
    assert_eq!(default["kind"], "builtin");
    assert_eq!(default["model"], "absent");
    assert!(s["disk"]["total"].is_u64());
    assert_eq!(s["disk"]["incomplete"], serde_json::Value::Null);
    // The gateway is not running, and nothing in the sandbox listens.
    assert_eq!(s["dashboard"], "absent");
    // The host reaches a Seatbelt sandbox's listeners: no command to name.
    assert_eq!(s["dashboard_command"], serde_json::Value::Null);
    assert_eq!(s["network_listeners"], serde_json::json!({"known": []}));
    assert_eq!(json["complete"], true);
    assert_eq!(json["idle_days"], 30);
    assert!(json["bytes"].is_u64());
    assert_eq!(json["unlisted"], serde_json::json!([]));
    assert_eq!(
        json["suggestions"][0],
        serde_json::json!({
            "kind": "log_in",
            "target": "home",
            "reason": "Hermes is not logged in",
            "command": "enclos connect home -- hermes -p default setup"
        })
    );
}
