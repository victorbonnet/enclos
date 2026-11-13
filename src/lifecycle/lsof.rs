//! How enclos looks at processes on macOS: `/bin/ps` for the processes
//! (`ps`), `/usr/sbin/lsof` for the files they map (`programs`), markers'
//! holders and listeners, `/usr/sbin/sysctl` for the ephemeral ports. `proc`
//! gives the same on Linux; `lifecycle` picks one of the two as `host`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use super::listeners::ListenersError;
use super::marker::{Held, MarkerError};

pub use super::programs::{lsof_name as program_name, program_files};
pub use super::ps::{group_of, processes, seen};

/// The TCP addresses each of `pids` listens on, with the pid that holds it.
pub fn tcp_listeners_of(pids: &[u32]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    lsof(&["-a", "-p", &list, "-iTCP", "-sTCP:LISTEN"])
}

/// Every process `lsof` shows listening on TCP at 127.0.0.1 port `port`.
pub fn tcp_listeners_at(port: u16) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    lsof(&[&format!("-iTCP@127.0.0.1:{port}"), "-sTCP:LISTEN"])
}

pub fn all_tcp_listeners() -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    lsof(&["-iTCP", "-sTCP:LISTEN"])
}

/// The uid of the connected client socket. The reverse (accepted) socket
/// belongs to enclos and must never be mistaken for the caller. Missing,
/// unreadable, malformed or conflicting ownership fails closed.
pub fn tcp_client_owner(client: SocketAddr, server: SocketAddr) -> std::io::Result<Option<u32>> {
    let output = super::bounded::output_within(
        Command::new("/usr/sbin/lsof").env("LC_ALL", "C").args([
            "-nP",
            "-a",
            &format!("-iTCP@{}:{}", client.ip(), client.port()),
            "-sTCP:ESTABLISHED",
            "-Fpun",
        ]),
        super::bounded::LIMIT,
    )?;
    if !output.status.success() && !(output.status.code() == Some(1) && output.stdout.is_empty()) {
        return Err(std::io::Error::other(
            "lsof could not identify the dashboard client",
        ));
    }
    Ok(client_owner(
        &String::from_utf8_lossy(&output.stdout),
        client,
        server,
    ))
}

fn client_owner(text: &str, client: SocketAddr, server: SocketAddr) -> Option<u32> {
    let wanted = format!("{client}->{server}");
    let mut uid = None;
    let mut owners = std::collections::BTreeSet::new();
    for line in text.lines() {
        if line.starts_with('p') {
            uid = None;
        } else if let Some(value) = line.strip_prefix('u') {
            uid = value.parse::<u32>().ok();
        } else if line.strip_prefix('n') == Some(wanted.as_str()) {
            owners.insert(uid?);
        }
    }
    if owners.len() == 1 {
        owners.into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod dashboard_owner_tests {
    use super::*;

    #[test]
    fn client_uid_is_not_the_accepted_sockets_uid_and_ambiguous_owners_are_refused() {
        let client = "127.0.0.1:59001".parse().unwrap();
        let server = "127.0.0.1:41002".parse().unwrap();
        let caller = "p10\nu1001\nn127.0.0.1:59001->127.0.0.1:41002\n";
        let accepted = "p11\nu1000\nn127.0.0.1:41002->127.0.0.1:59001\n";
        assert_eq!(
            client_owner(&format!("{accepted}{caller}"), client, server),
            Some(1001)
        );
        for text in [
            accepted.to_owned(),
            caller.replace("u1001", "ux"),
            caller.replace("u1001\n", ""),
            format!("{caller}{}", caller.replace("u1001", "u1002")),
        ] {
            assert_eq!(client_owner(&text, client, server), None, "{text}");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_kernel_names_the_real_loopback_client() {
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let server = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(
            tcp_client_owner(client.local_addr().unwrap(), server).unwrap(),
            Some(rustix::process::getuid().as_raw())
        );
    }
}

/// The first and last port the system picks from for a bind on port 0.
pub fn ephemeral_ports() -> Result<(u16, u16), String> {
    Ok((
        sysctl_port("net.inet.ip.portrange.first")?,
        sysctl_port("net.inet.ip.portrange.last")?,
    ))
}

/// The processes holding each named marker in `dir`. `lsof +d` reads the
/// folder itself, so what `marker::holders` read of it is not used here.
pub fn marker_holders(dir: &Path, _entries: std::fs::ReadDir) -> Result<Held, MarkerError> {
    // `-w`: a warning about another file system (an unreachable network
    // mount) is not a failure to look at this folder.
    let out = super::bounded::output_within(
        Command::new("/usr/sbin/lsof")
            .env("LC_ALL", "C")
            .args(["-nP", "-w", "-Fpn", "+d"])
            .arg(dir),
        super::bounded::LIMIT,
    )
    .map_err(|e| MarkerError::Lsof(e.to_string()))?;
    parse_markers(&out)
}

/// The command that names the program listening at `port`.
pub fn port_holders_command(port: u16) -> String {
    format!("lsof -nP -iTCP:{port} -sTCP:LISTEN")
}

fn lsof(select: &[&str]) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let out = Command::new("/usr/sbin/lsof")
        .env("LC_ALL", "C")
        .arg("-nP")
        .args(select)
        .arg("-Fn")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ListenersError::Lsof(e.to_string()))?;
    listening(&out)
}

/// What `lsof -Fn` answered. For processes with no such socket, or none at
/// all, it prints nothing and exits 1, with nothing on stderr; when one of
/// several is gone, it prints what the others hold and still exits 1 (macOS
/// 26.5.2). Any other failure, or a line that is not an address, means it
/// could not look.
fn listening(out: &Output) -> Result<Vec<(u32, SocketAddr)>, ListenersError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(1), true, true) => return Ok(Vec::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => {
            return Err(ListenersError::Lsof(format!(
                "{}{}",
                out.status,
                match why.as_str() {
                    "" => String::new(),
                    why => format!(": {why}"),
                }
            )));
        }
    }
    let mut found = Vec::new();
    let mut pid = None;
    for line in text.lines() {
        // A `p<pid>` line starts each process; `f<fd>` names a descriptor.
        if let Some(p) = line.strip_prefix('p') {
            pid = Some(
                p.parse()
                    .map_err(|_| ListenersError::Lsof(format!("unexpected process `{p}`")))?,
            );
        } else if let Some(name) = line.strip_prefix('n') {
            let pid = pid.ok_or_else(|| {
                ListenersError::Lsof(format!("an address before any process: `{name}`"))
            })?;
            let addr = address(name)
                .ok_or_else(|| ListenersError::Lsof(format!("unexpected address `{name}`")))?;
            found.push((pid, addr));
        }
    }
    Ok(found)
}

/// `127.0.0.1:61374`, `[::1]:8080` or `*:9000`.
fn address(name: &str) -> Option<SocketAddr> {
    let (host, port) = name.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let ip: IpAddr = match host {
        "*" => Ipv4Addr::UNSPECIFIED.into(),
        _ => host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .parse()
            .ok()?,
    };
    Some(SocketAddr::new(ip, port))
}

fn sysctl_port(name: &str) -> Result<u16, String> {
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", name])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run /usr/sbin/sysctl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.success() {
        true => text
            .trim()
            .parse()
            .map_err(|_| format!("sysctl gave `{}` for {name}", text.trim())),
        false => Err(format!("sysctl could not read {name}: {}", out.status)),
    }
}

/// What `lsof -Fpn +d` answered: a `p<pid>` line for each process, then an
/// `n<path>` line for each file of the folder it holds, the folder itself
/// for a process working in it. With nothing held it prints nothing and
/// exits 1, as for listeners.
fn parse_markers(out: &Output) -> Result<Held, MarkerError> {
    let text = String::from_utf8_lossy(&out.stdout);
    let why = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    match (out.status.code(), text.trim().is_empty(), why.is_empty()) {
        (Some(1), true, true) => return Ok(Held::new()),
        (Some(0), false, _) | (Some(1), false, true) => {}
        _ => return Err(MarkerError::Lsof(format!("{}: {why}", out.status))),
    }
    let mut held = Held::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = Some(
                p.parse::<u32>()
                    .map_err(|_| MarkerError::Lsof(format!("unexpected process `{p}`")))?,
            );
        } else if let Some(name) = line.strip_prefix('n') {
            let file = Path::new(name)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| n.starts_with("root-"));
            if let (Some(file), Some(pid)) = (file, pid) {
                held.entry(file.to_owned()).or_default().insert(pid);
            }
        }
    }
    Ok(held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn out(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn listeners_are_read_from_the_name_lines() {
        let got = listening(&out(
            0,
            "p32653\nf22\nn127.0.0.1:61374\nf23\nn[::1]:61374\nf24\nn*:9000\np41\nf5\nn127.0.0.1:61374\n",
            "",
        ))
        .unwrap();
        assert_eq!(
            got,
            [
                (32653, "127.0.0.1:61374".parse().unwrap()),
                (32653, "[::1]:61374".parse().unwrap()),
                (32653, "0.0.0.0:9000".parse().unwrap()),
                (41, "127.0.0.1:61374".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn nothing_listed_is_no_listener_but_any_other_failure_is_an_error() {
        assert!(listening(&out(1, "", "")).unwrap().is_empty());
        // One of several gone: what the others hold, and exit 1.
        assert_eq!(
            listening(&out(1, "p7\nf3\nn127.0.0.1:80\n", "")).unwrap(),
            [(7, "127.0.0.1:80".parse().unwrap())]
        );
        assert!(listening(&out(1, "", "lsof: illegal option")).is_err());
        assert!(listening(&out(2, "", "")).is_err());
        assert!(listening(&out(0, "", "")).is_err());
        assert!(listening(&out(0, "p1\nf3\nnsomething odd\n", "")).is_err());
        assert!(listening(&out(0, "f3\nn127.0.0.1:80\n", "")).is_err());
    }

    #[test]
    fn lsof_output_gives_each_sessions_holders() {
        let held = parse_markers(&out(
            0,
            "p100\nf3\nn/e/sandboxes/home/members/root-7-a\np200\nfcwd\nn/e/sandboxes/home/members\nf4\nn/e/sandboxes/home/members/root-7-a\nf5\nn/e/sandboxes/home/members/root-9-b\np300\nf3\nn/e/sandboxes/home/members/starting-1-2\n",
            "",
        ))
        .unwrap();
        assert_eq!(held["root-7-a"], BTreeSet::from([100, 200]));
        assert_eq!(held["root-9-b"], BTreeSet::from([200]));
        assert_eq!(held.len(), 2, "{held:?}");
    }

    #[test]
    fn nothing_held_is_no_holder_and_a_failure_is_an_error() {
        assert!(parse_markers(&out(1, "", "")).unwrap().is_empty());
        assert!(parse_markers(&out(1, "", "lsof: status error")).is_err());
        assert!(parse_markers(&out(0, "pnope\n", "")).is_err());
    }
}
