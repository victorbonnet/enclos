//! What `status` says of a bubblewrap sandbox's listeners (design §8,
//! Status). Its sessions listen in the sandbox's own network namespace,
//! which the host's network does not reach (ADR 0039, ADR 0040): `status`
//! names none of them as reachable, and does not fail to tell.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Stdio;
use std::time::Duration;

use super::{Lab, on_a_runner, once_there, text};

/// A listener on every address, in Python: writes its port to the file
/// named first, in the home, then answers each connection with `wide`,
/// and exits once that file is gone.
const WIDE: &str = r#"
import os, socket, sys
s = socket.socket()
s.bind(("0.0.0.0", 0))
s.listen()
s.settimeout(0.2)
path = os.path.join(os.environ["HOME"], sys.argv[1])
with open(path + ".tmp", "w") as f:
    f.write(str(s.getsockname()[1]))
os.rename(path + ".tmp", path)
while os.path.exists(path):
    try:
        c, _ = s.accept()
    except socket.timeout:
        continue
    c.sendall(b"wide")
    c.close()
"#;

/// The runner's own address on its network: the one it would send from to
/// a public address. A UDP socket's `connect` sends nothing.
fn runner_address() -> IpAddr {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(!ip.is_loopback() && !ip.is_unspecified(), "{ip}");
    ip
}

/// Whether a connection to `at` gets an answer, within 5 seconds.
fn answers(at: SocketAddr) -> bool {
    TcpStream::connect_timeout(&at, Duration::from_secs(5)).is_ok()
}

/// With its runtime's service running (a stand-in for Hermes's gateway, on
/// 127.0.0.1) and a session listening on every address, `status` can tell
/// the sandbox's listeners, and names none as reachable from the host's
/// network: from the runner's own address, the session's port is refused.
/// The control: a listener of the host's on every address is reached there.
#[test]
fn on_a_runner_status_tells_a_bubblewrap_sandboxs_listeners() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    lab.with_stand_in_hermes();
    lab.ok(&["sandbox", "start", "lab"]);
    lab.gateway(None, Duration::from_secs(60));
    let flag = lab.sandbox_home().join("wide.port");
    let mut wide = lab
        .command(&["connect", "lab", "--", "/usr/bin/python3", "-c", WIDE])
        .arg("wide.port")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let port: u16 = once_there(&flag).trim().parse().unwrap();
    // Recorded as its session once it runs: give `launch` that long.
    std::thread::sleep(Duration::from_secs(1));

    let out = lab.command(&["status", "lab"]).output().unwrap();
    let address = runner_address();
    let sandboxed = answers(SocketAddr::new(address, port));
    let host = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let control = answers(SocketAddr::new(address, host.local_addr().unwrap().port()));
    let tree = std::process::Command::new("/bin/sh")
        .args(["-c", "ps -o pid,ppid,args -u \"$(id -u)\""])
        .output()
        .unwrap();

    std::fs::remove_file(&flag).unwrap();
    let ended = wide.wait().unwrap();
    assert!(ended.success(), "{ended:?}");

    let said = text(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        !said.contains("listeners: cannot tell"),
        "{said}\n{}",
        text(&tree.stdout)
    );
    assert!(!said.contains("your network can reach"), "{said}");
    assert!(!sandboxed, "the session's port {port} answered at {address}");
    assert!(control, "the host's listener did not answer at {address}");
}
