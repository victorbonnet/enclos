use super::*;

fn out(file: &str) -> OutAttachment {
    OutAttachment {
        file: file.to_owned(),
        mime: "image/png".to_owned(),
        name: "folder/unicorn.png".to_owned(),
        size: 4,
    }
}

#[test]
fn a_file_of_the_media_folder_is_moved_into_the_bridges() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a1.png"), b"\x89PNG").unwrap();
    let taken = take_attachment(&inbox, &media, "c-1", &out("a1.png")).unwrap();
    assert_eq!(
        (taken.size, taken.name.as_str(), taken.mime.as_str()),
        (4, "unicorn.png", "image/png")
    );
    assert_eq!(std::fs::read(media.join(&taken.id)).unwrap(), b"\x89PNG");
    assert!(!inbox.join("a1.png").exists(), "moved, not copied");
}

#[test]
fn a_link_a_path_or_a_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(dir.path().join("secret"), b"host file").unwrap();
    std::os::unix::fs::symlink(dir.path().join("secret"), inbox.join("link.png")).unwrap();
    std::fs::create_dir(inbox.join("folder")).unwrap();
    for file in [
        "link.png",
        "../secret",
        "/etc/hosts",
        ".hidden",
        "folder",
        "",
    ] {
        assert!(
            take_attachment(&inbox, &media, "c-1", &out(file)).is_err(),
            "{file:?}"
        );
    }
    assert_eq!(
        std::fs::read(dir.path().join("secret")).unwrap(),
        b"host file"
    );
}

#[test]
fn a_strange_media_type_is_a_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a2.bin"), b"x").unwrap();
    let mut a = out("a2.bin");
    a.mime = "text/html; <script>".to_owned();
    assert_eq!(
        take_attachment(&inbox, &media, "c-1", &a).unwrap().mime,
        "application/octet-stream"
    );
}

/// A hub serving `lab/<name>` for each of `names`, each with its plugin's
/// socket in `dir`, and no device yet.
fn hub(dir: &std::path::Path, names: &[&str]) -> Arc<Hub> {
    let agents = names
        .iter()
        .map(|name| AgentEndpoint {
            name: format!("lab/{name}"),
            runtime: "hermes".to_owned(),
            socket: dir.join(format!("{name}.sock")),
            token: "t0ken".to_owned(),
        })
        .collect();
    Arc::new(Hub::new(
        Transport::Tailscale,
        dir.join("bridge.db"),
        vec![7; 32],
        agents,
        Some("alice@example.com".to_owned()),
    ))
}

/// One connection of a stand-in plugin: its `hello`'s capabilities, the
/// `commands` it sends then, and whether it closes after.
struct Answer {
    capabilities: Vec<Capability>,
    commands: Option<Vec<Command>>,
    closes: bool,
}

/// A stand-in plugin at `socket`: answers each connection in turn as
/// `answers` say, the last one kept open until the bridge closes it.
fn stand_in_plugin(socket: &std::path::Path, answers: Vec<Answer>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for answer in answers {
            let (stream, _) = listener.accept().unwrap();
            let mut out = stream.try_clone().unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).unwrap();
            let mut send = |body: FromPlugin| {
                let id = MessageId::new(new_id().unwrap()).unwrap();
                out.write_all(&encode_line(&Envelope::new(id, body)))
                    .unwrap();
            };
            send(FromPlugin::Hello {
                runtime: "hermes".into(),
                agent: "main".into(),
                capabilities: answer.capabilities,
            });
            if let Some(commands) = answer.commands {
                send(FromPlugin::Commands { commands });
            }
            if !answer.closes {
                while lines.read_until(b'\n', &mut line).unwrap_or(0) > 0 {}
            }
        }
    });
}

fn command(name: &str, description: &str) -> Command {
    Command {
        name: name.to_owned(),
        description: description.to_owned(),
        args: None,
    }
}

/// Waits up to 5 seconds for `done`.
fn until(done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "never came");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn an_agents_commands_are_cleaned_kept_and_sent_to_every_device() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["main"]);
    stand_in_plugin(
        &dir.path().join("main.sock"),
        vec![
            Answer {
                capabilities: vec![Capability::Commands],
                commands: Some(vec![
                    command("new", "Start\u{202E} a new\n session"),
                    command("Bad Name", "left out"),
                ]),
                closes: true,
            },
            Answer {
                capabilities: Vec::new(),
                commands: None,
                closes: false,
            },
        ],
    );
    let (alice, from_alice) = channel();
    let (bob, from_bob) = channel();
    {
        let mut devices = hub.devices.lock().unwrap();
        devices.insert("d-1".to_owned(), ("alice@example.com".to_owned(), alice));
        devices.insert("d-2".to_owned(), ("bob@example.com".to_owned(), bob));
    }
    let listed = |commands: Vec<Command>| ToDevice::Commands {
        agent: "lab/main".to_owned(),
        commands,
    };
    let cleaned = vec![command("new", "Start a new session")];

    hub.plugin("lab/main").unwrap();
    for device in [&from_alice, &from_bob] {
        let got = device.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, listed(cleaned.clone()));
    }
    // Kept once the plugin is gone, and sent after the agents' list.
    until(|| !hub.plugins.lock().unwrap().contains_key("lab/main"));
    let answer = hub.agents_answer();
    assert!(matches!(&answer[0], ToDevice::AgentsList { agents } if agents.len() == 1));
    assert_eq!(answer[1..], [listed(cleaned)]);

    // Connected again without the capability: its old list is dropped.
    hub.plugin("lab/main").unwrap();
    for device in [&from_alice, &from_bob] {
        let got = device.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, listed(Vec::new()));
    }
    assert_eq!(hub.agents_answer().len(), 1);
}

#[test]
fn a_plugin_that_stalls_its_hello_holds_up_no_other_agent() {
    let dir = tempfile::tempdir().unwrap();
    let hub = hub(dir.path(), &["slow", "main"]);
    // `slow` takes the connection and says nothing until released.
    let slow = std::os::unix::net::UnixListener::bind(dir.path().join("slow.sock")).unwrap();
    let (accepted, was_accepted) = channel();
    let (release, released) = channel::<()>();
    std::thread::spawn(move || {
        let (stream, _) = slow.accept().unwrap();
        accepted.send(()).unwrap();
        let _ = released.recv();
        drop(stream);
    });
    stand_in_plugin(
        &dir.path().join("main.sock"),
        vec![Answer {
            capabilities: vec![Capability::Commands],
            commands: None,
            closes: false,
        }],
    );

    hub.open_plugins();
    was_accepted.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(hub.opening_all.load(Ordering::SeqCst), "one pass, running");
    hub.open_plugins(); // another request while it runs: no second pass

    let started = std::time::Instant::now();
    assert!(matches!(
        &hub.agents_answer()[0],
        ToDevice::AgentsList { .. }
    ));
    hub.plugin("lab/main").unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "waited {:?} on another agent's hello",
        started.elapsed()
    );

    drop(release);
    until(|| !hub.opening_all.load(Ordering::SeqCst));
    assert!(!hub.plugins.lock().unwrap().contains_key("lab/slow"));
}
