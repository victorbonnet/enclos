//! The egress proxy: one per sandbox, the sandbox's only way out (ADRs 0007,
//! 0017). A domain-level CONNECT proxy without TLS interception: it checks
//! the destination against the allowlist, resolves the name itself, connects
//! only to validated addresses, and logs every connection it decides on
//! (design §6 says when a record can be missing).
//!
//! It reads the sandbox's active policy for each new connection, so
//! `enclos policy allow` applies without a restart.

pub mod decide;
mod hello;
pub mod request;
mod server;
mod stream;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;

use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::net::addr::{AddrClass, classify};
use crate::state::{NetLogStore, StateStore};

pub(crate) use server::Slot;
pub use stream::Listener;

/// The descriptors a proxy keeps for itself: the standard streams, its
/// listeners, the state database.
const OWN_DESCRIPTORS: u64 = 24;

/// The most descriptors a proxy plans for, however many the service manager
/// gives it: its connections and lookups also hold threads, which nothing
/// else bounds.
const MOST_DESCRIPTORS: u64 = 1024;

/// The most client connections a proxy serves at once, and the most name
/// lookups that run at once, for a process limited to `descriptors` (none:
/// no limit). A connection holds a thread, two while it relays, and two
/// descriptors. A lookup, which counts until the host's resolver returns
/// even if the proxy stopped waiting for it, holds a thread, and possibly a
/// descriptor while the resolver waits. Connections and lookups share what
/// is left after [`OWN_DESCRIPTORS`] at the rate of 100 to 32, which fills
/// the 256 launchd gives a service, and neither is ever none.
fn limits_for(descriptors: Option<u64>) -> (usize, usize) {
    const SHARE: u64 = 2 * 100 + 32;
    let left = descriptors
        .unwrap_or(MOST_DESCRIPTORS)
        .min(MOST_DESCRIPTORS)
        .saturating_sub(OWN_DESCRIPTORS);
    let share = |rate: u64| ((left * rate / SHARE) as usize).max(1);
    (share(100), share(32))
}

/// How long resolving a destination's name and connecting to its addresses
/// may take in all.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection may go without a byte moving either way, or a peer
/// without reading, before the proxy closes it. Generous on purpose, for
/// long-lived streams and model requests sent without streaming (design §6,
/// Limits).
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Where the proxy gets the policy it enforces.
pub trait PolicySource: Send + Sync {
    fn policy(&self) -> Result<Policy, String>;
}

/// Name resolution, done by the proxy, never by the sandbox.
pub trait Resolve: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The host's resolver. It has no deadline of its own beyond the operating
/// system's.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}

/// The sandbox's active policy, read from the state store each time.
pub struct ActivePolicy<S> {
    pub store: S,
    pub sandbox: SandboxName,
}

impl<S: StateStore + Send + Sync> PolicySource for ActivePolicy<S> {
    fn policy(&self) -> Result<Policy, String> {
        match self.store.active_policy(&self.sandbox) {
            Ok(Some((_, snapshot))) => Ok(snapshot.policy),
            Ok(None) => Err(format!("sandbox {} has no policy", self.sandbox)),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct Proxy {
    sandbox: SandboxName,
    policy: Box<dyn PolicySource>,
    log: Box<dyn NetLogStore + Send + Sync>,
    resolver: Arc<dyn Resolve>,
    classify: fn(IpAddr) -> AddrClass,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connections: usize,
    max_lookups: usize,
    /// Lookups still running, including those the proxy stopped waiting for.
    /// Kept here, not per `serve`, because a lookup outlives its connection.
    lookups: Arc<AtomicUsize>,
    /// Whether the proxy said on stderr that the lookups are full, since a
    /// lookup last started.
    lookups_full: AtomicBool,
    /// Client connections open now, on every listener: the limit is the
    /// proxy's, not each listener's.
    open: Arc<AtomicUsize>,
}

impl Proxy {
    pub fn new(
        sandbox: SandboxName,
        policy: Box<dyn PolicySource>,
        log: Box<dyn NetLogStore + Send + Sync>,
    ) -> Proxy {
        // The soft limit is the one a descriptor hits: what the service
        // manager gave, as the proxy never raises it.
        let descriptors = rustix::process::getrlimit(rustix::process::Resource::Nofile).current;
        let (max_connections, max_lookups) = limits_for(descriptors);
        Proxy {
            sandbox,
            policy,
            log,
            resolver: Arc::new(SystemResolver),
            classify,
            connect_timeout: CONNECT_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            max_connections,
            max_lookups,
            lookups: Arc::new(AtomicUsize::new(0)),
            lookups_full: AtomicBool::new(false),
            open: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The same proxy with another resolver and address check, for tests
    /// that serve from loopback.
    #[cfg(test)]
    fn for_tests(mut self, resolver: Box<dyn Resolve>, classify: fn(IpAddr) -> AddrClass) -> Proxy {
        self.resolver = Arc::from(resolver);
        self.classify = classify;
        self
    }
}

/// A listener the proxy could not open.
#[derive(Debug)]
pub struct ListenError {
    pub addr: SocketAddr,
    pub source: io::Error,
}

/// The proxy's listeners at `port`, on both loopbacks. The Seatbelt rule
/// opens the port to TCP on loopback (design §5), and on macOS 26.5.2 that
/// was shown to include `[::1]` as well as `127.0.0.1`, so the proxy holds
/// both: any address it left free at the port, another program could
/// listen on, and the sandbox would reach it around the proxy.
///
/// `[::1]` comes first, so that once `127.0.0.1` answers, both are held.
/// Port 0 means any port: the one `[::1]` got is used for `127.0.0.1` too.
/// Where `[::1]` is not configured (binding it fails with "address not
/// available"), no program can listen there, so `127.0.0.1` alone is
/// served; that is said on stderr. Any other failure on either address is
/// an error, and leaves neither listened on.
pub fn listen(port: u16) -> Result<Vec<TcpListener>, ListenError> {
    let bind =
        |addr: SocketAddr| TcpListener::bind(addr).map_err(|source| ListenError { addr, source });
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let mut listeners = Vec::new();
    let mut port = port;
    match bind(v6) {
        Ok(listener) => {
            port = listener
                .local_addr()
                .map_err(|source| ListenError { addr: v6, source })?
                .port();
            listeners.push(listener);
        }
        Err(e) if e.source.kind() == io::ErrorKind::AddrNotAvailable => eprintln!(
            "enclos proxy: [::1] is not configured here, so no program can listen on [::1]:{port}; serving 127.0.0.1 only. Restart the proxy if IPv6 loopback is turned on later."
        ),
        Err(e) => return Err(e),
    }
    listeners.push(bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?);
    Ok(listeners)
}

/// The proxy's listener on the Unix socket at `path`, whose folder exists.
/// A socket already there is taken over if nothing answers on it, as after
/// a proxy that was killed. Anything else there, or a proxy answering, is
/// an error.
pub fn listen_unix(path: &Path) -> io::Result<UnixListener> {
    match UnixListener::bind(path) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            let left = std::fs::symlink_metadata(path)?.file_type().is_socket()
                && UnixStream::connect(path).is_err();
            if !left {
                return Err(e);
            }
            std::fs::remove_file(path)?;
            UnixListener::bind(path)
        }
        bound => bound,
    }
}

#[cfg(test)]
mod tests;
