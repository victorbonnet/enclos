//! The egress proxy: one per sandbox, the sandbox's only way out (ADRs 0007,
//! 0017). A domain-level CONNECT proxy without TLS interception: it checks
//! the destination against the allowlist, resolves the name itself, connects
//! only to validated addresses, and logs every connection it decides on
//! (design §6 says when a record can be missing).
//!
//! It reads the sandbox's active policy for each new connection, so
//! `enclos policy allow` applies without a restart.

pub mod decide;
pub mod request;
mod server;

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;

use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::net::addr::{AddrClass, classify};
use crate::state::{NetLogStore, StateStore};

/// The most client connections a proxy serves at once. Each holds a thread,
/// two while it relays, and two file descriptors; launchd starts services
/// with a limit of 256 descriptors, which these and `MAX_LOOKUPS` stay
/// within.
const MAX_CONNECTIONS: usize = 100;

/// The most name lookups that run at once, counting those the proxy stopped
/// waiting for, which go on until the host's resolver returns. Each holds a
/// thread, and possibly a descriptor while the resolver waits.
const MAX_LOOKUPS: usize = 32;

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
}

impl Proxy {
    pub fn new(
        sandbox: SandboxName,
        policy: Box<dyn PolicySource>,
        log: Box<dyn NetLogStore + Send + Sync>,
    ) -> Proxy {
        Proxy {
            sandbox,
            policy,
            log,
            resolver: Arc::new(SystemResolver),
            classify,
            connect_timeout: CONNECT_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
            max_lookups: MAX_LOOKUPS,
            lookups: Arc::new(AtomicUsize::new(0)),
            lookups_full: AtomicBool::new(false),
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

    /// Binds the sandbox's listener, then serves it until the process ends.
    /// Returns only if serving stopped, as an error, so the service manager
    /// restarts the proxy.
    pub fn run(self, addr: SocketAddr) -> io::Result<()> {
        let socket = TcpListener::bind(addr)?;
        let _ = Arc::new(self).serve(socket)?.join();
        Err(io::Error::other("the proxy stopped accepting connections"))
    }
}

#[cfg(test)]
mod tests;
