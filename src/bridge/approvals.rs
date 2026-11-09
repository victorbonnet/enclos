//! Approval requests cross the trust boundary as data. Only the host's person decides.
use super::*;
use crate::{
    engine::Engine,
    model::{audit::Actor, sandbox::SandboxName},
};
use enclos_protocol::approval::{Access, AccessKind, Approval};

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
        if let Some(mut existing) = store
            .approvals()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|a| {
                a.sandbox == sandbox
                    && a.access == access
                    && (a.state == "pending" || a.state == "applying")
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
        let policy = sandbox
            .parse::<SandboxName>()
            .ok()
            .and_then(|n| Engine::open(self.layout.clone()).policy(&n).ok())
            .map(|v| v.snapshot.id.to_string())
            .unwrap_or_default();
        let mut key = crate::policy::sha256_hex(
            format!(
                "{sandbox}:{policy}:{}",
                serde_json::to_string(&access).map_err(|e| e.to_string())?
            )
            .as_bytes(),
        );
        if let Some(old) = store.approval(&key).map_err(|e| e.to_string())? {
            if old.state != "diagnostic" {
                return Ok(());
            }
            // A later genuine attempt gets a new id; stale decisions for the test stay closed.
            key = crate::policy::sha256_hex(format!("{key}:after-diagnostic").as_bytes());
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
        preview(&Engine::open(self.layout.clone()), &mut a);
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

    pub(super) fn collect_refusals(&self, store: &Store) -> Result<(), String> {
        self.dismiss_probe_requests(store)?;
        let engine = Engine::open(self.layout.clone());
        let sandboxes: std::collections::HashSet<_> = self
            .agents
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

    pub(super) fn decide_access(
        self: &Arc<Self>,
        store: &Store,
        device: &Device,
        person: &str,
        id: &str,
        revision: &str,
        approve: bool,
    ) -> Result<(), String> {
        if self.host.as_deref() != Some(person) {
            return Err("Only the host's person can decide sandbox policy requests. The host's identity must be known.".into());
        }
        // Recheck revocation immediately before the decision, not just at the handshake.
        if !store
            .devices()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|d| d.id == device.id && d.person == person)
        {
            return Err("This device is no longer paired.".into());
        }
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
        if a.state != "pending" {
            self.deliver(person, ToDevice::Approval(a));
            return Ok(());
        }
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
