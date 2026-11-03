//! Ports for tests' own listeners, kept clear of enclos's proxy range.
//!
//! Linux's ephemeral range holds the proxy range, so a bind on port 0 can
//! land on a port a test sandbox's proxy wants, or one the engine refuses as
//! a service's. Whatever binds on port 0 in a test comes through here: Rust
//! through [`tcp_listener`] or [`clear_of_proxies`], the stand-ins through
//! [`perl_listener`] or [`python_listener`], each with the same rule. A port
//! rejected stays held while the next is asked for, so the system gives
//! another; it is let go at the end.

use std::net::{IpAddr, TcpListener};

use crate::model::sandbox::{PORT_FIRST, PORT_LAST};

/// How many ports are tried before giving up.
const TRIES: usize = 64;

/// The first of what `next` gives, each with its port, whose port is outside
/// the proxy range. Panics after [`TRIES`].
pub(crate) fn clear_of_proxies<T>(mut next: impl FnMut() -> (T, u16)) -> T {
    let mut rejected = Vec::new();
    for _ in 0..TRIES {
        let (held, port) = next();
        if !(PORT_FIRST..=PORT_LAST).contains(&port) {
            return held;
        }
        rejected.push(held);
    }
    panic!("no port outside {PORT_FIRST} to {PORT_LAST} in {TRIES} tries");
}

/// A TCP listener at `address`, on a port the system chooses.
pub(crate) fn tcp_listener(address: impl Into<IpAddr>) -> TcpListener {
    let address = address.into();
    clear_of_proxies(|| {
        let listener = TcpListener::bind((address, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    })
}

/// Perl defining `listener($address, $port, $reuse)`: a listening socket at
/// a packed address, on `$port` or else one the system chooses, shared with
/// `SO_REUSEPORT` when `$reuse` is true.
pub(crate) fn perl_listener() -> String {
    format!(
        r#"use Socket qw(:all);
sub clear {{ my ($next) = @_; my @rejected; for (1..{TRIES}) {{ my ($held, $port) = $next->(); return $held if $port < {PORT_FIRST} || $port > {PORT_LAST}; push @rejected, $held; }} die "no port outside {PORT_FIRST} to {PORT_LAST} in {TRIES} tries\n"; }}
sub listener {{ my ($at, $port, $reuse) = @_; my $s = clear(sub {{ socket(my $s, PF_INET, SOCK_STREAM, 0) or die "socket: $!\n"; if ($reuse) {{ setsockopt($s, SOL_SOCKET, SO_REUSEPORT, 1) or die "setsockopt: $!\n"; }} bind($s, sockaddr_in($port // 0, $at)) or die "bind: $!\n"; ($s, (sockaddr_in(getsockname($s)))[0]) }}); listen($s, 1) or die "listen: $!\n"; $s }}
"#
    )
}

/// Python defining `listener()`: a listening socket at 127.0.0.1, on a port
/// the system chooses.
#[cfg(target_os = "linux")]
pub(crate) fn python_listener() -> String {
    format!(
        r#"import socket
def clear(next_one):
    rejected = []
    for _ in range({TRIES}):
        held, port = next_one()
        if not {PORT_FIRST} <= port <= {PORT_LAST}:
            return held
        rejected.append(held)
    raise SystemExit("no port outside {PORT_FIRST} to {PORT_LAST} in {TRIES} tries")
def bound():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    return s, s.getsockname()[1]
def listener():
    s = clear(bound)
    s.listen()
    return s
"#
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::process::Command;
    #[cfg(target_os = "linux")]
    use std::process::Output;

    use super::*;

    /// The ports a stand-in is given: the range's edges and middle first.
    const IN_RANGE_FIRST: [u16; 4] = [PORT_FIRST, 41500, PORT_LAST, PORT_FIRST - 1];

    /// Counts its drops, to show what is held while the next port is asked for.
    struct Held<'a>(&'a RefCell<usize>);

    impl Drop for Held<'_> {
        fn drop(&mut self) {
            *self.0.borrow_mut() += 1;
        }
    }

    #[test]
    fn a_port_in_the_range_is_held_while_the_next_is_asked_for_then_let_go() {
        let dropped = RefCell::new(0);
        let mut ports = IN_RANGE_FIRST.into_iter();
        let mut asked = 0;
        let held = clear_of_proxies(|| {
            assert_eq!(*dropped.borrow(), 0);
            asked += 1;
            (Held(&dropped), ports.next().unwrap())
        });
        assert_eq!(asked, 4);
        assert_eq!(*dropped.borrow(), 3);
        drop(held);
    }

    #[test]
    fn the_ports_next_to_the_range_are_outside_it() {
        for port in [PORT_FIRST - 1, PORT_LAST + 1] {
            assert_eq!(clear_of_proxies(|| (port, port)), port);
        }
    }

    #[test]
    #[should_panic(expected = "no port outside 41000 to 41999 in 64 tries")]
    fn a_source_of_nothing_but_the_range_fails_loudly() {
        clear_of_proxies(|| ((), PORT_FIRST));
    }

    #[test]
    fn a_listener_is_on_a_port_outside_the_range() {
        let listener = tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        assert!(!(PORT_FIRST..=PORT_LAST).contains(&port), "{port}");
    }

    #[cfg(target_os = "linux")]
    fn python(program: &str) -> Output {
        Command::new("/usr/bin/python3")
            .args(["-I", "-c", program])
            .output()
            .unwrap()
    }

    #[test]
    fn perl_takes_the_first_port_outside_the_range() {
        let ports = IN_RANGE_FIRST.map(|p| p.to_string()).join(", ");
        let out = Command::new("/usr/bin/perl")
            .args([
                "-e",
                &format!(
                    "{}my @ports = ({ports}); print clear(sub {{ my $p = shift @ports; ($p, $p) }});",
                    perl_listener()
                ),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(out.stdout, (PORT_FIRST - 1).to_string().as_bytes());
    }

    #[test]
    fn perl_fails_loudly_on_nothing_but_the_range() {
        let out = Command::new("/usr/bin/perl")
            .args([
                "-e",
                &format!("{}clear(sub {{ (0, {PORT_FIRST}) }});", perl_listener()),
            ])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{out:?}");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains("in 64 tries"), "{said}");
    }

    /// A real socket, sharing its port when asked: what the stand-ins use.
    #[test]
    fn a_perl_listener_says_a_port_outside_the_range() {
        let out = Command::new("/usr/bin/perl")
            .args([
                "-e",
                &format!(
                    "{}my $s = listener(INADDR_LOOPBACK, undef, 1); print((sockaddr_in(getsockname($s)))[0]);",
                    perl_listener()
                ),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let port: u16 = String::from_utf8_lossy(&out.stdout).parse().unwrap();
        assert!(!(PORT_FIRST..=PORT_LAST).contains(&port), "{port}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn python_takes_the_first_port_outside_the_range() {
        let ports = IN_RANGE_FIRST.map(|p| p.to_string()).join(", ");
        let out = python(&format!(
            "{}ports = iter([{ports}])\ndef offered():\n    p = next(ports)\n    return p, p\nprint(clear(offered), end='')\n",
            python_listener()
        ));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(out.stdout, (PORT_FIRST - 1).to_string().as_bytes());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn python_fails_loudly_on_nothing_but_the_range() {
        let out = python(&format!(
            "{}clear(lambda: (0, {PORT_FIRST}))\n",
            python_listener()
        ));
        assert!(!out.status.success(), "{out:?}");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(said.contains("in 64 tries"), "{said}");
    }
}
