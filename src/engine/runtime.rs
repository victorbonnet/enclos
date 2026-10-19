//! The engine's runtime calls: install a runtime in a sandbox, log it in, and
//! manage its agents (design §9 "Runtime adapter", §12).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use super::Engine;
use super::session::SessionEnd;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::runtime::{HomeFile, RuntimeAdapter, adapter};

impl Engine {
    /// The runtime installed in the sandbox.
    pub(super) fn runtime_of(&self, name: &SandboxName) -> Result<RuntimeKind> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        record.runtime.ok_or_else(|| Error::Session {
            what: format!("sandbox {name} has no runtime yet. Install one with `enclos runtime install hermes --sandbox {name}`"),
        })
    }

    pub(super) fn agent_of(&self, name: &SandboxName, agent: &str) -> Result<AgentRecord> {
        self.runtime_of(name)?;
        self.state
            .agents(name)?
            .into_iter()
            .find(|p| p.name.as_str() == agent)
            .ok_or_else(|| Error::Session {
                what: format!("sandbox {name} has no agent `{agent}`. Add it with `enclos agent add {name}/{agent}`"),
            })
    }

    /// Installs `kind` in the sandbox: its endpoints join the policy as a new
    /// version, its installer is downloaded on the host and run only if it is
    /// the reviewed one, inside the sandbox, through the proxy, in this
    /// terminal (ADR 0021).
    pub fn install_runtime(
        &self,
        by: &Actor,
        name: &SandboxName,
        kind: RuntimeKind,
    ) -> Result<SessionEnd> {
        let runtime = adapter(kind);
        let installer_file = self.write(
            by,
            "runtime install",
            Some(format!("{name} {kind}")),
            |_| "prepared".to_owned(),
            |lock| {
                let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                    name: name.to_string(),
                })?;
                if let Some(other) = record.runtime.filter(|a| *a != kind) {
                    return Err(Error::Session {
                        what: format!(
                            "sandbox {name} already has {other}; one runtime per sandbox (ADR 0003)"
                        ),
                    });
                }
                record.runtime = Some(kind);
                self.state.put(lock, &record)?;
                let overrides = self.layout.read_policy(name.as_str())?;
                self.save_policy(lock, by, name, &overrides)?;
                self.stage_install(name, runtime.as_ref())
            },
        )?;
        self.run_in_sandbox(by, name, installer_file, "runtime install run")
    }

    /// Stages what an install needs in the sandbox's `installers/` folder,
    /// beside its home: the sandbox can read it but not write it, so the
    /// host never writes through a link the sandbox planted. Returns the
    /// command that installs: it copies the adapter's files into the home
    /// from inside the sandbox, under its policy, then runs the installer.
    fn stage_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<Vec<std::ffi::OsString>> {
        let dir = self.layout.sandbox_dir(name.as_str()).join("installers");
        let io = |path: &std::path::Path| {
            let path = path.to_owned();
            move |source| Error::Layout(LayoutError::Io { path, source })
        };
        std::fs::create_dir_all(&dir).map_err(io(&dir))?;
        let files = runtime.home_files();
        let mut staged = Vec::new();
        for (i, file) in files.iter().enumerate() {
            let path = dir.join(format!("home-{i}"));
            std::fs::write(&path, file.contents).map_err(io(&path))?;
            staged.push((path, file));
        }
        let installer = self.download_installer(&dir, runtime)?;
        let mut script = home_files_script(&staged);
        script.push_str("exec /bin/bash \"$0\" \"$@\"\n");
        let mut command: Vec<std::ffi::OsString> = vec![
            "/bin/sh".into(),
            "-c".into(),
            script.into(),
            installer.into_os_string(),
        ];
        command.extend(runtime.installer().args.iter().map(Into::into));
        Ok(command)
    }

    /// Downloads the runtime's installer on the host into `dir`, outside the
    /// sandbox home, and keeps it only if its SHA-256 is the reviewed one.
    fn download_installer(
        &self,
        dir: &std::path::Path,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<PathBuf> {
        let installer = runtime.installer();
        let path = dir.join(format!("{}-install.sh", runtime.kind()));
        let failed = |what: String| Error::Session { what };
        let status = Command::new("/usr/bin/curl")
            .args(["-fsSL", "--max-time", "120", "-o"])
            .arg(&path)
            .arg(installer.url)
            .stdin(Stdio::null())
            .status()
            .map_err(|e| failed(format!("cannot run curl: {e}")))?;
        if !status.success() {
            return Err(failed(format!(
                "could not download {} ({status})",
                installer.url
            )));
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| failed(format!("cannot read {}: {e}", path.display())))?;
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if got != installer.sha256 {
            let _ = std::fs::remove_file(&path);
            return Err(failed(format!(
                "the {} installer at {} changed (sha256 {got}); enclos runs only the version it was reviewed against ({}). Update enclos",
                runtime.kind(),
                installer.url,
                installer.sha256
            )));
        }
        Ok(path)
    }

    /// The runtime's own login and model choice, in this terminal.
    pub fn runtime_login(&self, by: &Actor, name: &SandboxName) -> Result<SessionEnd> {
        let kind = self.runtime_of(name)?;
        self.run_in_sandbox(by, name, adapter(kind).login(), "runtime login")
    }

    /// Adds an agent: the runtime creates it inside the sandbox, and enclos
    /// records it. Nothing else changes: the policy and the proxy are the
    /// sandbox's (ADR 0024).
    pub fn add_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: AgentName,
    ) -> Result<AgentRecord> {
        let kind = self.runtime_of(name)?;
        if self.state.agents(name)?.iter().any(|p| p.name == agent) {
            return Err(Error::Session {
                what: format!("sandbox {name} already has agent {agent}"),
            });
        }
        let created = self.run_in_sandbox(
            by,
            name,
            adapter(kind).create_agent(&agent),
            "agent add run",
        )?;
        if created.exit != 0 {
            return Err(Error::Session {
                what: format!(
                    "{kind} could not create agent {agent} (exit {})",
                    created.exit
                ),
            });
        }
        self.write(
            by,
            "agent add",
            Some(format!("{name}/{agent}")),
            |_| "added".to_owned(),
            |lock| {
                let added = AgentRecord {
                    name: agent.clone(),
                    created_at: now(),
                };
                self.state.put_agent(lock, name, &added)?;
                Ok(added)
            },
        )
    }

    /// The sandbox's home folder, which is `~` for everything that runs in it.
    pub fn sandbox_home(&self, name: &SandboxName) -> std::path::PathBuf {
        self.layout.sandbox_home(name.as_str())
    }

    pub fn agents(&self, name: &SandboxName) -> Result<Vec<AgentRecord>> {
        self.runtime_of(name)?;
        Ok(self.state.agents(name)?)
    }

    /// Removes an agent's record. Its files stay in the sandbox home; the
    /// runtime's own commands remove them.
    pub fn remove_agent(&self, by: &Actor, name: &SandboxName, agent: &AgentName) -> Result<()> {
        self.agent_of(name, agent.as_str())?;
        self.write(
            by,
            "agent rm",
            Some(format!("{name}/{agent}")),
            |_| "removed".to_owned(),
            |lock| {
                self.state
                    .remove_agent(lock, name, agent)
                    .map_err(Into::into)
            },
        )
    }
}

/// The `sh` lines that copy staged files into the sandbox home. They run
/// inside the sandbox, so a link the sandbox planted can only lead where
/// the sandbox may write anyway.
pub(crate) fn home_files_script(staged: &[(PathBuf, &HomeFile)]) -> String {
    let mut script = String::from("set -e\n");
    for (path, file) in staged {
        let target = format!("\"$HOME\"/{}", sh_word(file.path));
        let mode = if file.executable { "700" } else { "600" };
        script.push_str(&format!(
            "mkdir -p \"$(dirname {target})\"\ncp {} {target}\nchmod {mode} {target}\n",
            sh_word(&path.display().to_string())
        ));
    }
    script
}

/// `s` as one `sh` word.
fn sh_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
