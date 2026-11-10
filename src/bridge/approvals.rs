//! Approval requests cross the trust boundary as data. Only the host's person decides.
use super::*;
use crate::{
    engine::Engine,
    model::{audit::Actor, sandbox::SandboxName},
};
use enclos_protocol::approval::{Access, AccessKind, Approval};

struct ApprovalGeneration {
    fingerprint: String,
    created_second: i64,
}

impl ApprovalGeneration {
    fn includes(&self, request: &Approval) -> bool {
        match request.request.split_once(':') {
            Some((generation, _)) => generation == self.fingerprint,
            // Legacy cards predate generation-prefixed IDs. Their clock
            // has seconds, so preserve the ambiguous creation second.
            None => request.time >= self.created_second,
        }
    }

    fn request_key(&self, digest: &str) -> String {
        format!("{}:{digest}", self.fingerprint)
    }
}

fn approval_generation(engine: &Engine, name: &SandboxName) -> Option<ApprovalGeneration> {
    Some(ApprovalGeneration {
        fingerprint: engine.sandbox_generation(name).ok()?,
        created_second: engine.sandbox_created_at(name).ok()?.as_second(),
    })
}

fn diagnostic_access(access: &Access) -> bool {
    access.kind == AccessKind::Network
        && crate::net::host::AllowEntry::parse(&access.target)
            .is_ok_and(|entry| entry.host_text() == crate::probes::POLICY_PROBE_HOST)
}

fn preview(engine: &Engine, a: &mut Approval) {
    match a
        .sandbox
        .parse::<SandboxName>()
        .map_err(|e| e.to_string())
        .and_then(|n| engine.access_plan(&n, &a.access).map_err(|e| e.to_string()))
    {
        Ok(p) => {
            a.change = p.change;
            a.restart = p.restart;
            a.revision = p.revision;
            a.available = true;
            a.reason = None;
        }
        Err(e) => {
            a.available = false;
            a.reason = Some(e);
        }
    }
}

impl Hub {
    pub(super) fn request_access(
        &self,
        store: &Store,
        agent: &str,
        conversation: Option<&str>,
        access: Access,
        action: &str,
    ) -> Result<(), String> {
        if diagnostic_access(&access) {
            return if agent.contains('/') {
                Err("This is an Enclos diagnostic probe destination, not an access request to approve.".into())
            } else {
                Ok(())
            };
        }
        let sandbox = agent.split('/').next().unwrap_or(agent);
        // Bounds apply before storage or display. No tool arguments or output are copied.
        if access.target.is_empty()
            || access.target.len() > 4096
            || access.target.chars().any(char::is_control)
        {
            return Err("invalid access target".into());
        }
        let engine = Engine::open(self.layout.clone());
        let name = sandbox.parse::<SandboxName>().ok();
        let generation = name
            .as_ref()
            .and_then(|name| approval_generation(&engine, name));
        if generation.is_none()
            && name
                .as_ref()
                .is_some_and(|name| engine.require_sandbox(name).is_ok())
        {
            return Err("Cannot identify this sandbox generation. Review it on the host before requesting access.".into());
        }
        if generation.is_some()
            && let Some(person) = &self.host
        {
            self.retire_removed_sandbox_requests(store, sandbox, "bridge", person)?;
        }
        let generation = name
            .as_ref()
            .and_then(|name| approval_generation(&engine, name));
        if let Some(mut existing) = store
            .approvals()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|a| {
                a.sandbox == sandbox
                    && a.access == access
                    && generation
                        .as_ref()
                        .is_none_or(|generation| generation.includes(a))
                    && matches!(a.state.as_str(), "pending" | "applying" | "failed")
            })
        {
            // An authenticated agent's explicit request must not be mistaken for a probe.
            if existing.state == "pending" && existing.agent.is_empty() && agent.contains('/') {
                existing.agent = agent.into();
                existing.conversation = conversation.map(str::to_owned);
                existing.action = action
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(240)
                    .collect();
                if !store
                    .refresh_approval(&existing)
                    .map_err(|e| e.to_string())?
                {
                    return self.request_access(store, agent, conversation, access, action);
                }
                if let Some(person) = &self.host {
                    self.deliver(person, ToDevice::Approval(existing));
                }
            }
            return Ok(());
        }
        let policy = name
            .as_ref()
            .and_then(|name| engine.policy(name).ok())
            .map(|v| v.snapshot.id.to_string())
            .unwrap_or_default();
        let legacy_key = crate::policy::sha256_hex(
            format!(
                "{sandbox}:{policy}:{}",
                serde_json::to_string(&access).map_err(|e| e.to_string())?
            )
            .as_bytes(),
        );
        // Keep existing same-generation legacy decisions as history and
        // deduplication, without binding them to a later sandbox of the name.
        if let Some(generation) = &generation {
            let after_diagnostic =
                crate::policy::sha256_hex(format!("{legacy_key}:after-diagnostic").as_bytes());
            for legacy in [&legacy_key, &after_diagnostic] {
                if let Some(old) = store.approval(legacy).map_err(|error| error.to_string())?
                    && generation.includes(&old)
                    && old.state != "diagnostic"
                {
                    return Ok(());
                }
            }
        }
        let mut key = generation
            .as_ref()
            .map(|generation| generation.request_key(&legacy_key))
            .unwrap_or_else(|| legacy_key.clone());
        if let Some(old) = store.approval(&key).map_err(|e| e.to_string())? {
            if old.state != "diagnostic" {
                return Ok(());
            }
            // A later genuine attempt gets a new id; stale decisions for the test stay closed.
            let after_diagnostic =
                crate::policy::sha256_hex(format!("{legacy_key}:after-diagnostic").as_bytes());
            key = generation
                .as_ref()
                .map(|generation| generation.request_key(&after_diagnostic))
                .unwrap_or(after_diagnostic);
            if store.approval(&key).map_err(|e| e.to_string())?.is_some() {
                return Ok(());
            }
        }
        let mut a = Approval {
            request: key,
            sandbox: sandbox.into(),
            agent: if agent.contains('/') {
                agent.into()
            } else {
                String::new()
            },
            conversation: conversation.map(str::to_owned),
            access,
            action: action
                .chars()
                .filter(|c| !c.is_control())
                .take(240)
                .collect(),
            time: now(),
            state: "pending".into(),
            change: String::new(),
            restart: false,
            revision: String::new(),
            available: false,
            reason: None,
        };
        preview(&engine, &mut a);
        if !store.create_approval(&a).map_err(|e| e.to_string())? {
            return Ok(());
        }
        if let Some(person) = &self.host {
            self.deliver(person, ToDevice::Approval(a));
        }
        Ok(())
    }

    fn only_probe_events(&self, a: &Approval) -> bool {
        if !a.agent.is_empty() || a.access.kind != AccessKind::Network {
            return false;
        }
        let Ok(name) = a.sandbox.parse::<SandboxName>() else {
            return false;
        };
        let Ok(target) = crate::net::host::AllowEntry::parse(&a.access.target) else {
            return false;
        };
        let engine = Engine::open(self.layout.clone());
        let matches = |d: &crate::model::net::DeniedDestination| {
            d.host == target.host_text()
                && d.port == target.port
                && matches!(
                    d.reason,
                    crate::model::net::Reason::NotAllowed
                        | crate::model::net::Reason::PrivateAddress
                )
        };
        let Ok(all) = engine.net_denied(&name) else {
            return false;
        };
        let Ok(ordinary) = engine.net_denied_for_approval(&name) else {
            return false;
        };
        all.iter().any(matches) && !ordinary.iter().any(matches)
    }

    pub(super) fn dismiss_probe_requests(&self, store: &Store) -> Result<(), String> {
        for a in store.approvals().map_err(|e| e.to_string())? {
            if a.state == "pending"
                && (diagnostic_access(&a.access) || self.only_probe_events(&a))
                && let Some(closed) = store.dismiss_probe(&a).map_err(|e| e.to_string())?
                && let Some(person) = &self.host
            {
                self.deliver(person, ToDevice::Approval(closed));
            }
        }
        Ok(())
    }

    /// Retires attention for an absent sandbox or a request from an older
    /// generation of its name. Legacy cards of the current generation stay.
    /// The requests remain as history; an in-flight decision keeps its claim.
    pub(super) fn retire_removed_sandbox_requests(
        &self,
        store: &Store,
        sandbox: &str,
        device: &str,
        person: &str,
    ) -> Result<(), String> {
        use crate::state::{StateStore, sqlite::SqliteStateStore};

        if self.host.as_deref() != Some(person) {
            return Err("Only the host's person can retire its sandbox policy requests.".into());
        }
        let name = sandbox
            .parse::<SandboxName>()
            .map_err(|error| error.to_string())?;
        let state = SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock());
        // A CLI create uses this same lock: no fresh sandbox of this name
        // can appear between confirming absence and closing old attention.
        let _lock = state.lock().map_err(|error| error.to_string())?;
        let engine = Engine::open(self.layout.clone());
        let generation = match engine.require_sandbox(&name) {
            Ok(()) => Some(approval_generation(&engine, &name).ok_or(
                "Cannot identify the sandbox generation; policy requests were left unchanged.",
            )?),
            Err(crate::error::Error::NoSuchSandbox { .. }) => None,
            Err(error) => return Err(error.to_string()),
        };
        for request in store.approvals().map_err(|error| error.to_string())? {
            if request.sandbox == sandbox
                && matches!(request.state.as_str(), "pending" | "failed")
                && generation
                    .as_ref()
                    .is_none_or(|generation| !generation.includes(&request))
                && store
                    .close_approval(&request.request, device, person)
                    .map_err(|error| error.to_string())?
                && let Some(closed) = store
                    .approval(&request.request)
                    .map_err(|error| error.to_string())?
            {
                self.deliver(person, ToDevice::Approval(closed));
            }
        }
        Ok(())
    }

    pub(super) fn collect_refusals(&self, store: &Store) -> Result<(), String> {
        self.dismiss_probe_requests(store)?;
        let engine = Engine::open(self.layout.clone());
        let endpoints = self.agent_endpoints()?;
        let sandboxes: std::collections::HashSet<_> = endpoints
            .iter()
            .filter_map(|a| a.name.split_once('/').map(|(s, _)| s))
            .collect();
        for sandbox in sandboxes {
            let Ok(name) = sandbox.parse::<SandboxName>() else {
                continue;
            };
            let policy = engine
                .policy(&name)
                .map_err(|e| e.to_string())?
                .snapshot
                .policy;
            for d in engine
                .net_denied_for_approval(&name)
                .map_err(|e| e.to_string())?
                .into_iter()
                .take(200)
            {
                use crate::model::net::Reason;
                if d.host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(crate::probes::POLICY_PROBE_HOST)
                {
                    continue;
                }
                if !matches!(d.reason, Reason::NotAllowed | Reason::PrivateAddress) {
                    continue;
                }
                if let Ok(dest) = crate::proxy::decide::Destination::parse(&d.host, d.port) {
                    let allowed = crate::proxy::decide::allowed(&policy, &dest);
                    if allowed
                        && (d.reason != Reason::PrivateAddress
                            || policy.net.private.contains(&d.host))
                    {
                        continue;
                    }
                }
                let target = crate::model::net::destination(&d.host, d.port);
                // The log is sandbox-wide: do not invent a requesting agent or conversation.
                self.request_access(
                    store,
                    sandbox,
                    None,
                    Access {
                        kind: AccessKind::Network,
                        target: target.clone(),
                        private: d.reason == Reason::PrivateAddress,
                    },
                    &format!("Connect to {target}"),
                )?;
            }
        }
        Ok(())
    }

    fn approval_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
    ) -> Result<(), String> {
        if self.host.as_deref() != Some(person) {
            return Err("Only the host's person can decide sandbox policy requests. The host's identity must be known.".into());
        }
        // Recheck revocation immediately before the action, not just at the handshake.
        if !store
            .devices()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|d| d.id == device.id && d.person == person)
        {
            return Err("This device is no longer paired.".into());
        }
        Ok(())
    }

    pub(super) fn close_access(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        id: &str,
    ) -> Result<(), String> {
        self.approval_authority(store, device, person)?;
        // The store transition also checks the state atomically against other devices.
        store
            .close_approval(id, &device.id, person)
            .map_err(|e| e.to_string())?;
        let a = store
            .approval(id)
            .map_err(|e| e.to_string())?
            .ok_or("Unknown policy request")?;
        let applying = a.state == "applying";
        self.deliver(person, ToDevice::Approval(a));
        if applying {
            return Err(
                "This request is already being decided. Wait for the result before closing it."
                    .into(),
            );
        }
        Ok(())
    }

    pub(super) fn decide_access(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        id: &str,
        revision: &str,
        approve: bool,
    ) -> Result<(), String> {
        self.approval_authority(store, device, person)?;
        let mut a = store
            .approval(id)
            .map_err(|e| e.to_string())?
            .ok_or("Unknown policy request")?;
        if a.state == "pending" && (diagnostic_access(&a.access) || self.only_probe_events(&a)) {
            if let Some(closed) = store.dismiss_probe(&a).map_err(|e| e.to_string())? {
                self.deliver(person, ToDevice::Approval(closed));
            }
            return Err("This is an Enclos diagnostic probe; no approval is needed.".into());
        }
        if matches!(a.state.as_str(), "pending" | "failed") {
            self.retire_removed_sandbox_requests(store, &a.sandbox, &device.id, person)?;
            a = store
                .approval(id)
                .map_err(|error| error.to_string())?
                .ok_or("Unknown policy request")?;
            if a.state == "closed" {
                return Ok(());
            }
        }
        if a.state != "pending" {
            self.deliver(person, ToDevice::Approval(a));
            return Ok(());
        }
        let _busy = self.claim_sandbox_busy(&a.sandbox)?;
        let engine = Engine::open(self.layout.clone());
        if approve {
            preview(&engine, &mut a);
            if !a.available || a.revision != revision {
                if !store.refresh_approval(&a).map_err(|e| e.to_string())? {
                    return Err("This request was decided on another device.".into());
                }
                self.deliver(person, ToDevice::Approval(a));
                return Err("The policy changed or this scope cannot be approved. Review the request's current details.".into());
            }
        }
        if !store.claim_approval(id).map_err(|e| e.to_string())? {
            return Err("This request is already being decided on another device.".into());
        }
        a.state = "applying".into();
        self.deliver(person, ToDevice::Approval(a.clone()));
        let by = Actor {
            user: format!("{person} (device {}, request {id})", device.id),
            host: self.layout.data().display().to_string(),
        };
        let name = a
            .sandbox
            .parse::<SandboxName>()
            .map_err(|e| e.to_string())?;
        let result = if approve {
            engine
                .approve_access(&by, &name, &a.access, revision)
                .map(|_| ())
        } else {
            engine.deny_access(&by, &name, id)
        };
        match result {
            Ok(()) => {
                a.state = if approve { "approved" } else { "denied" }.into();
                a.reason = None;
            }
            Err(e) => {
                a.state = "failed".into();
                a.reason = Some(format!(
                    "{e}. Review the active and pending policy on the host before retrying."
                ));
            }
        }
        store.put_approval(&a).map_err(|e| e.to_string())?;
        self.deliver(person, ToDevice::Approval(a.clone()));
        // Knowledge is the active policy, never a speculative grant from a button press.
        self.refresh_access_context(&a.sandbox);
        Ok(())
    }

    pub(super) fn refresh_access_context(self: &Arc<Self>, sandbox: &str) {
        let Ok(name) = sandbox.parse::<SandboxName>() else {
            return;
        };
        if let Ok(text) = Engine::open(self.layout.clone()).access_context(&name) {
            let mut plugins = self.plugins.lock().expect("not poisoned");
            for (agent, (writer, caps)) in plugins.iter_mut() {
                if agent.split('/').next() == Some(sandbox) && caps.contains(&Capability::Approval)
                {
                    let _ = writer.send(FromBridge::PolicyContext { text: text.clone() });
                }
            }
        }
        self.open_plugins();
    }
}
