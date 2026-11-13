use super::policy::with_sandbox;
use super::*;
use crate::engine::listener::{Network, NoPort, outside_proxy_range, service_listener};
use crate::lifecycle::marker::spawn_unmarked;
use crate::model::runtime::RuntimeKind;
use crate::model::session::{ProcessRef, SessionId, SessionKind, SessionRecord};

/// A stand-in gateway: `perl` running `script`, which prints each port
/// it listens on, one a line, then waits.
fn perl(script: &str, ports: usize) -> (std::process::Child, Vec<u16>) {
    use std::io::BufRead;
    let mut child = spawn_unmarked(
        std::process::Command::new("/usr/bin/perl")
            .args(["-MSocket=:all", "-e", script])
            .stdout(std::process::Stdio::piped()),
    )
    .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let ports = (0..ports)
        .map(|_| lines.next().unwrap().unwrap().parse().unwrap())
        .collect();
    (child, ports)
}

/// `ports` loopback listeners on ports the system chooses, as Hermes's
/// gateway binds `127.0.0.1:0`.
fn listening(ports: usize, at: &str) -> String {
    format!(
        "{}for (1..{ports}) {{ my $s = listener(inet_aton(\"{at}\")); push @s, $s; print((sockaddr_in(getsockname($s)))[0], qq(\\n)); }} $| = 1; STDOUT->flush; sleep 30",
        crate::test_ports::perl_listener()
    )
}

/// Records `root` as an open session of the sandbox's `gateway`, and
/// Hermes as its runtime.
pub(super) fn record_gateway(engine: &Engine, name: &SandboxName, root: ProcessRef) {
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(name)?.unwrap();
                record.runtime = Some(RuntimeKind::Hermes);
                engine.state.put(lock, &record)?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Service,
                    service: Some("gateway".to_owned()),
                    version: 1,
                    snapshot: engine.policy(name)?.snapshot.id,
                    compiled: None,
                    root,
                    pgid: None,
                    cgroup: None,
                    tracked: Vec::new(),
                    started_at: crate::model::now(),
                    ended_at: None,
                };
                engine.state.start_session(lock, &session, &record)?;
                Ok(())
            },
        )
        .unwrap();
}

/// A stand-in gateway listening on `ports` ports at 127.0.0.1, recorded
/// as the open session of the sandbox's `gateway` service.
pub(super) fn gateway(
    engine: &Engine,
    name: &SandboxName,
    ports: usize,
) -> (std::process::Child, u16) {
    // The kernel's ephemeral ports hold the proxy's range, which the
    // engine refuses in a gateway, so one that lands there is dropped.
    let proxy_ports = crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST;
    loop {
        let (child, held) = perl(&listening(ports, "127.0.0.1"), ports);
        if held.iter().any(|port| proxy_ports.contains(port)) {
            end(child);
            continue;
        }
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        record_gateway(engine, name, root);
        return (child, held[0]);
    }
}

pub(super) fn end(mut child: std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn connect_waits_for_nothing_when_the_gateway_listens() {
    let (_dir, engine, name) = with_sandbox();
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    let (child, _) = gateway(&engine, &name, 1);
    let got = engine.start_listener_service(&alice(), &name, &mut |_| panic!("said"));
    end(child);
    assert_eq!(got.unwrap(), None);
}

/// What waiting does not fix ends the wait at once.
#[test]
fn connect_stops_waiting_at_once_for_a_gateway_refused() {
    let (_dir, engine, name) = with_sandbox();
    let home = engine.layout.sandbox_home(name.as_str());
    std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
    let (child, _) = gateway(&engine, &name, 2);
    let begun = std::time::Instant::now();
    let got = engine.start_listener_service(&alice(), &name, &mut |_| {});
    end(child);
    assert!(begun.elapsed() < std::time::Duration::from_secs(10));
    let waited = got.unwrap().unwrap();
    assert!(!waited.started);
    let late = waited.late.unwrap();
    assert!(late.contains("listens on 2 ephemeral ports"), "{late}");
}

#[test]
fn the_service_port_is_the_one_its_own_process_holds() {
    let (_dir, engine, name) = with_sandbox();
    assert_eq!(
        engine.service_port(&engine.record(&name).unwrap()),
        Ok(None)
    );
    let (child, port) = gateway(&engine, &name, 1);
    let record = engine.record(&name).unwrap();
    assert_eq!(engine.service_port(&record), Ok(Some(port)));
    end(child);
    // Gone: no port, and the session is told why and what to do.
    let why = engine.service_port(&record).unwrap_err();
    assert!(why.contains("the gateway is not running"), "{why}");
    assert!(why.contains("enclos sandbox start home"), "{why}");
}

#[test]
fn a_service_holding_several_ports_gets_none_rather_than_a_guess() {
    let (_dir, engine, name) = with_sandbox();
    let (child, _) = gateway(&engine, &name, 2);
    let got = service_listener(engine.state.as_ref(), &name, "gateway", &Network::Host);
    end(child);
    assert!(
        matches!(&got, Err(NoPort::Refused(why)) if why.contains("listens on 2 ephemeral ports")),
        "{got:?}"
    );
}

#[test]
fn two_open_gateway_sessions_get_none_rather_than_a_guess() {
    let (_dir, engine, name) = with_sandbox();
    let (one, _) = gateway(&engine, &name, 1);
    let (two, _) = gateway(&engine, &name, 1);
    let got = service_listener(engine.state.as_ref(), &name, "gateway", &Network::Host);
    end(one);
    end(two);
    assert!(
        matches!(&got, Err(NoPort::Refused(why)) if why.contains("2 gateway sessions are running")),
        "{got:?}"
    );
}

#[test]
fn a_pid_now_another_processs_is_not_taken_for_the_gateway() {
    let (_dir, engine, name) = with_sandbox();
    // This test process listens, under the gateway's recorded pid but
    // not its start time, as when the pid was reused.
    let _listener = crate::test_ports::tcp_listener(std::net::Ipv4Addr::LOCALHOST);
    let root = ProcessRef {
        pid: std::process::id(),
        started: "Thu Jan  1 00:00:00 1970".to_owned(),
    };
    record_gateway(&engine, &name, root);
    let got = service_listener(engine.state.as_ref(), &name, "gateway", &Network::Host);
    assert!(
        matches!(&got, Err(NoPort::NotRunning(why)) if why.contains("not running")),
        "{got:?}"
    );
}

#[test]
fn a_gateway_on_every_address_or_sharing_its_port_gets_none() {
    // On every address: another process could hold 127.0.0.1 there.
    let (_dir, engine, name) = with_sandbox();
    let (child, held) = perl(&listening(1, "0.0.0.0"), 1);
    record_gateway(
        &engine,
        &name,
        crate::lifecycle::process::reference_of_child(&child).unwrap(),
    );
    let got = service_listener(engine.state.as_ref(), &name, "gateway", &Network::Host);
    end(child);
    assert!(
        matches!(&got, Err(NoPort::NotYet(why)) if why.contains("no TCP listener at 127.0.0.1")),
        "{held:?}"
    );

    // Sharing 127.0.0.1 at its port with another process (SO_REUSEPORT):
    // a session could reach that one too.
    let (_dir, engine, name) = with_sandbox();
    let shared = format!(
        "{}my $s = listener(INADDR_LOOPBACK, $ARGV[0], 1); print((sockaddr_in(getsockname($s)))[0], qq(\\n)); $| = 1; STDOUT->flush; sleep 30",
        crate::test_ports::perl_listener()
    );
    let (owner, port) = perl(&shared, 1);
    let mut other = spawn_unmarked(
        std::process::Command::new("/usr/bin/perl")
            .args(["-MSocket=:all", "-e", &shared, &port[0].to_string()])
            .stdout(std::process::Stdio::piped()),
    )
    .unwrap();
    {
        use std::io::BufRead;
        let mut lines = std::io::BufReader::new(other.stdout.take().unwrap()).lines();
        assert_eq!(lines.next().unwrap().unwrap(), port[0].to_string());
    }
    record_gateway(
        &engine,
        &name,
        crate::lifecycle::process::reference_of_child(&owner).unwrap(),
    );
    let got = service_listener(engine.state.as_ref(), &name, "gateway", &Network::Host);
    end(owner);
    end(other);
    let why = got.unwrap_err();
    assert!(
        matches!(&why, NoPort::Refused(why) if why.contains("also listens at 127.0.0.1")),
        "{why:?}"
    );
}

fn status_of(engine: &Engine, name: &SandboxName) -> crate::engine::SandboxStatus {
    let mut view = engine.status(Some(name)).unwrap();
    view.sandboxes.remove(0)
}

/// The gateway serves the SPA without its browser token, so its port is
/// not a usable dashboard. Status directs the user to a dedicated server.
#[test]
fn status_shows_a_dedicated_dashboard_command_instead_of_the_gateway_url() {
    use crate::engine::Fact;
    fn ready(engine: &Engine, name: &SandboxName) {
        std::fs::create_dir_all(engine.sandbox_home(name).join(".hermes/hermes-agent")).unwrap();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.record(name)?;
                    record.state = crate::model::sandbox::SandboxState::Running;
                    Ok(engine.state.put(lock, &record)?)
                },
            )
            .unwrap();
    }
    let (_dir, engine, name) = with_sandbox();
    let (child, _) = gateway(&engine, &name, 1);
    ready(&engine, &name);
    let up = status_of(&engine, &name);
    let command = Some(format!("enclos dashboard {name}"));
    assert!(
        serde_json::to_value(&up)
            .unwrap()
            .get("dashboard")
            .is_none()
    );
    assert_eq!(up.dashboard_command, command);
    let mut unsupported = engine.record(&name).unwrap();
    unsupported.backend = crate::model::sandbox::BackendKind::Bubblewrap;
    let runtime = crate::runtime::adapter(unsupported.runtime.unwrap());
    assert!(
        engine
            .dashboard_of(
                &unsupported,
                runtime.as_ref(),
                &super::super::listener::HostServices::default()
            )
            .is_err()
    );
    assert!(
        engine
            .sandbox_status(unsupported, Some(runtime.as_ref()), crate::model::now())
            .unwrap()
            .dashboard_command
            .is_none()
    );
    end(child);
    // On loopback alone: nothing the host's network reaches.
    assert_eq!(up.network_listeners, Fact::Known(Vec::new()));
    let stopped = status_of(&engine, &name);
    assert_eq!(stopped.dashboard_command, None);

    let (_dir, engine, name) = with_sandbox();
    let (child, _) = gateway(&engine, &name, 2);
    ready(&engine, &name);
    let several = status_of(&engine, &name);
    end(child);
    assert_eq!(several.dashboard_command, None);

    // The command does not depend on a gateway port, and listeners beyond
    // loopback are still named as reachable from the host's network.
    let (_dir, engine, name) = with_sandbox();
    let (child, held) = perl(&listening(1, "0.0.0.0"), 1);
    let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
    record_gateway(&engine, &name, root);
    ready(&engine, &name);
    let wide = status_of(&engine, &name);
    end(child);
    assert_eq!(wide.dashboard_command, None);
    let Fact::Known(reached) = wide.network_listeners else {
        panic!("{:?}", wide.network_listeners);
    };
    assert_eq!(reached.len(), 1, "{reached:?}");
    assert_eq!(reached[0].address, format!("*:{}", held[0]));
}

#[test]
fn a_proxy_port_is_never_a_sessions_service_port() {
    use crate::model::sandbox::{PORT_FIRST, PORT_LAST};
    assert!(outside_proxy_range(PORT_FIRST).is_err());
    assert!(outside_proxy_range(PORT_LAST).is_err());
    assert_eq!(outside_proxy_range(61374), Ok(61374));
}
