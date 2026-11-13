//! A dashboard on the host's network: its upstream is an inherited Unix
//! listener in the host-only run folder. The browser's TCP port comes from
//! outside the proxy range, so it cannot take another install's reservation.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::model::sandbox::{PORT_FIRST, PORT_LAST, SandboxName};
use crate::runtime::{RuntimeSocketDashboard, SandboxCommand};

pub(super) struct Local {
    pub listener: UnixListener,
    pub front: Option<TcpListener>,
    pub socket: PathBuf,
    pub script: PathBuf,
    pub command: SandboxCommand,
    pub port: u16,
    pub prefix: String,
}

impl Local {
    /// Called while the dashboard lock is held. Never removes a socket a
    /// running dashboard owns, nor reserves a sandbox's proxy port.
    pub fn prepare(
        engine: &Engine,
        name: &SandboxName,
        runtime: RuntimeSocketDashboard,
    ) -> Result<Self> {
        let prepare = || -> io::Result<Self> {
            // A host can configure its ephemeral range to overlap enclos's.
            // Keep rejected listeners held until selection ends, so the
            // kernel cannot keep handing back the same reserved port.
            let mut rejected = Vec::new();
            let front = loop {
                let candidate = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                if !(PORT_FIRST..=PORT_LAST).contains(&candidate.local_addr()?.port()) {
                    break candidate;
                }
                rejected.push(candidate);
            };
            let port = front.local_addr()?.port();
            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(io::Error::other)?;
            let capability: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let prefix = format!("/{capability}/");
            let socket = engine.layout.dashboard_socket(name.as_str());
            match std::fs::symlink_metadata(&socket) {
                Ok(found) if found.file_type().is_socket() => std::fs::remove_file(&socket)?,
                Ok(_) => return Err(io::Error::other("dashboard socket path is not a socket")),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let listener = UnixListener::bind(&socket)?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
            let folder = engine.layout.sandbox_installers(name.as_str());
            std::fs::create_dir_all(&folder)?;
            let script = folder.join("dashboard-socket.py");
            if let Err(error) = std::fs::write(&script, runtime.source) {
                let _ = std::fs::remove_file(&socket);
                return Err(error);
            }
            let mut words = runtime.launcher.into_words();
            words.push(script.as_os_str().to_owned());
            words.push(port.to_string().into());
            let command = SandboxCommand::new(words).reading(vec![script.clone()]);
            Ok(Self {
                listener,
                front: Some(front),
                socket,
                script,
                command,
                port,
                prefix,
            })
        };
        prepare().map_err(|error| Error::Dashboard {
            what: format!("cannot prepare the private dashboard of sandbox {name}: {error}"),
        })
    }

    /// Readiness comes from the server answering on the host-bound
    /// descriptor, never from sandbox stdout or a sandbox-written file.
    pub fn ready(&self) -> bool {
        let check = || -> io::Result<bool> {
            let mut stream = UnixStream::connect(&self.socket)?;
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            stream.set_write_timeout(Some(Duration::from_millis(200)))?;
            write!(
                stream,
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                self.port
            )?;
            let mut head = [0; 512];
            let n = stream.read(&mut head)?;
            let head = String::from_utf8_lossy(&head[..n]);
            Ok(head.starts_with("HTTP/1.1 200 ") || head.starts_with("HTTP/1.1 30"))
        };
        check().unwrap_or(false)
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.script);
    }
}
