//! The egress proxy: one per sandbox, the sandbox's only way out (ADRs 0007,
//! 0017). A domain-level CONNECT proxy without TLS interception: it checks
//! the destination against the allowlist, resolves the name itself, connects
//! only to validated addresses, and logs every connection.
//!
//! It reads the sandbox's active policy for each new connection, so
//! `enclos policy allow` applies without a restart.

pub mod decide;
pub mod request;
mod server;

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::model::policy::Policy;
use crate::model::sandbox::SandboxName;
use crate::net::addr::{AddrClass, classify};
use crate::state::{NetLogStore, StateStore};

/// Where the proxy gets the policy it enforces.
pub trait PolicySource: Send + Sync {
    fn policy(&self) -> Result<Policy, String>;
}

/// Name resolution, done by the proxy, never by the sandbox.
pub trait Resolve: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The host's resolver.
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

/// One listener: its address, and the profile whose traffic it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub addr: SocketAddr,
    pub profile: Option<String>,
}

pub struct Proxy {
    sandbox: SandboxName,
    policy: Box<dyn PolicySource>,
    log: Box<dyn NetLogStore + Send + Sync>,
    resolver: Box<dyn Resolve>,
    classify: fn(IpAddr) -> AddrClass,
    connect_timeout: Duration,
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
            resolver: Box::new(SystemResolver),
            classify,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// The same proxy with another resolver and address check, for tests
    /// that serve from loopback.
    #[cfg(test)]
    fn for_tests(mut self, resolver: Box<dyn Resolve>, classify: fn(IpAddr) -> AddrClass) -> Proxy {
        self.resolver = resolver;
        self.classify = classify;
        self
    }

    /// Binds every listener, then serves them until the process ends.
    pub fn run(self, listeners: &[Listener]) -> io::Result<()> {
        let bound = listeners
            .iter()
            .map(|l| TcpListener::bind(l.addr).map(|socket| (socket, l.profile.clone())))
            .collect::<io::Result<Vec<_>>>()?;
        let proxy = Arc::new(self);
        let handles: Vec<_> = bound
            .into_iter()
            .map(|(socket, profile)| proxy.serve(socket, profile))
            .collect();
        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
