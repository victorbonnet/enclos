//! Approval requests cross the trust boundary as data. Only the host's person decides.
use super::*;
use crate::{
    engine::Engine,
    model::{audit::Actor, sandbox::SandboxName},
};
use enclos_protocol::approval::{Access, AccessKind, Approval};

/// The most pending requests one sandbox may have: an agent that keeps
/// asking for new targets fills neither the inbox nor the bridge's store.
pub(super) const MAX_PENDING: usize = 50;

/// Whether a proxy refusal of `access`, last seen at `last` (seconds), has
/// already had its chance: it is older than the bridge's first collection
/// (`since`), or a request for the same scope was made after it. Then a
/// denial stays a denial when the policy later changes for another reason;
/// only a refusal after the request asks again.
pub(super) fn refusal_counted(
    known: &[Approval],
    sandbox: &str,
    access: &Access,
    last: i64,
    since: i64,
) -> bool {
    last < since
        || known
            .iter()
            .any(|a| a.sandbox == sandbox && &a.access == access && a.time >= last)
}

/// Whether `agent` (`<sandbox>/<agent>`, as its connection names it) may
/// file a policy request for conversation `id`: one of its own, or a group
/// it is a member of.
pub(super) fn speaks_in(store: &Store, agent: &str, id: &str) -> bool {
    store.conversation_info(id).ok().flatten().is_some_and(|c| {
        format!("{}/{}", c.sandbox, c.agent) == agent
            || store
                .members(id)
                .unwrap_or_default()
                .iter()
                .any(|(m, _)| format!("{}/{m}", c.sandbox) == agent)
    })
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
            a.scope = p.scope;
            a.restart = p.restart;
            a.revision = p.revision;
            a.available = true;
            a.reason = None;
        }
        Err(e) => {
            a.available = false;
            a.scope.clear();
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
        let sandbox = agent.split('/').next().unwrap_or(agent);
        // Bounds apply before storage or display. No tool arguments or output are copied.
        if access.target.is_empty()
            || access.target.len() > 4096
            || enclos_protocol::visible::has_hidden(&access.target, false)
        {
            return Err("invalid access target".into());
        }
        // One request per scope, however the agent spells it
        let access = crate::engine::normalized(&access);
        let open = store.approvals().map_err(|e| e.to_string())?;
        if open.iter().any(|a| {
            a.sandbox == sandbox
                && a.access == access
                && (a.state == "pending" || a.state == "applying")
        }) {
            return Ok(());
        }
        if open
            .iter()
            .filter(|a| a.sandbox == sandbox && a.state == "pending")
            .count()
            >= MAX_PENDING
        {
            // A proxy refusal waits for the next collection; an agent is told.
            return if agent.contains('/') {
                Err(format!(
                    "{sandbox} already has {MAX_PENDING} pending policy requests. Wait for the person to decide them."
                ))
            } else {
                Ok(())
            };
        }
        let policy = sandbox
            .parse::<SandboxName>()
            .ok()
            .and_then(|n| {
                Engine::open(self.layout.clone(), crate::state::Wait::Background)
                    .policy(&n)
                    .ok()
            })
            .map(|v| v.snapshot.id.to_string())
            .unwrap_or_default();
        let key = crate::policy::sha256_hex(
            format!(
                "{sandbox}:{policy}:{}",
                serde_json::to_string(&access).map_err(|e| e.to_string())?
            )
            .as_bytes(),
        );
        // Decided under this policy: not asked again until it changes. An
        // agent is told so, not left waiting for a request nobody sees.
        // One that failed (the bridge stopped mid-decision, the state lock
        // was busy) changed nothing: it is asked again
        let known = store.approval(&key).map_err(|e| e.to_string())?;
        let reopen = known.as_ref().is_some_and(|k| k.state == "failed");
        if let Some(known) = known.filter(|_| !reopen) {
            return if agent.contains('/') && !matches!(known.state.as_str(), "pending" | "applying")
            {
                Err(format!(
                    "A request for this scope was already {} under {sandbox}'s active policy. It is not asked again until the policy changes.",
                    known.state
                ))
            } else {
                Ok(())
            };
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
            action: enclos_protocol::visible::stripped(action, false)
                .chars()
                .take(240)
                .collect(),
            time: now(),
            state: "pending".into(),
            change: String::new(),
            scope: String::new(),
            restart: false,
            revision: String::new(),
            available: false,
            reason: None,
        };
        preview(
            &Engine::open(self.layout.clone(), crate::state::Wait::Background),
            &mut a,
        );
        let stored = if reopen {
            store.reopen_approval(&a)
        } else {
            store.create_approval(&a)
        };
        if !stored.map_err(|e| e.to_string())? {
            return Ok(());
        }
        if let Some(person) = self.known_host() {
            self.deliver(&person, ToDevice::Approval(a));
        }
        Ok(())
    }

    /// Turns the proxies' recent refusals into policy requests. A refusal
    /// counts once: one older than the bridge's first collection, or seen
    /// last before a request for the same scope was made, already had its
    /// chance, so a denial is not asked again after an unrelated policy
    /// change; only a new refusal after it is.
    pub(super) fn collect_refusals(&self, store: &Store) -> Result<(), String> {
        let since = store.refusals_since().map_err(|e| e.to_string())?;
        let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
        let sandboxes: std::collections::HashSet<_> = self
            .agents
            .iter()
            .filter_map(|a| a.name.split_once('/').map(|(s, _)| s))
            .collect();
        for sandbox in sandboxes {
            let Ok(name) = sandbox.parse::<SandboxName>() else {
                continue;
            };
            // One sandbox that cannot be read does not stop the others.
            let (policy, denied) = match engine
                .policy(&name)
                .and_then(|view| Ok((view.snapshot.policy, engine.net_denied(&name)?)))
            {
                Ok(read) => read,
                Err(e) => {
                    eprintln!("enclos app approvals: {sandbox}: {e}");
                    continue;
                }
            };
            let denied: Vec<_> = denied.into_iter().take(200).collect();
            // Only the requests a refusal still to be counted can match:
            // this sandbox's, made since the oldest of them was last seen.
            let Some(from) = denied
                .iter()
                .map(|d| d.last.as_second())
                .filter(|&last| last >= since)
                .min()
            else {
                continue;
            };
            let known = match store.approvals_since(sandbox, from) {
                Ok(known) => known,
                Err(e) => {
                    eprintln!("enclos app approvals: {sandbox}: {e}");
                    continue;
                }
            };
            for d in denied {
                use crate::model::net::Reason;
                if !matches!(d.reason, Reason::NotAllowed | Reason::PrivateAddress) {
                    continue;
                }
                let target = crate::model::net::destination(&d.host, d.port);
                let private = d.reason == Reason::PrivateAddress;
                let access = Access {
                    kind: AccessKind::Network,
                    target: target.clone(),
                    private,
                };
                if refusal_counted(&known, sandbox, &access, d.last.as_second(), since) {
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
                // The log is sandbox-wide: do not invent a requesting agent or conversation.
                self.request_access(
                    store,
                    sandbox,
                    None,
                    access,
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
        if self.known_host().as_deref() != Some(person) {
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
        if a.state != "pending" {
            self.deliver(person, ToDevice::Approval(a));
            return Ok(());
        }
        let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
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

    fn refresh_access_context(self: &Arc<Self>, sandbox: &str) {
        let Ok(name) = sandbox.parse::<SandboxName>() else {
            return;
        };
        if let Ok(text) =
            Engine::open(self.layout.clone(), crate::state::Wait::Background).access_context(&name)
        {
            // Written outside the plugins lock, each through its plugin's own
            let outs: Vec<_> = {
                let plugins = self.plugins.lock().expect("not poisoned");
                plugins
                    .iter()
                    .filter(|(agent, plugin)| {
                        agent.split('/').next() == Some(sandbox)
                            && plugin.capabilities.contains(&Capability::Approval)
                    })
                    .map(|(_, plugin)| Arc::clone(&plugin.out))
                    .collect()
            };
            for out in outs {
                let _ = out
                    .lock()
                    .expect("not poisoned")
                    .writer
                    .send(FromBridge::PolicyContext { text: text.clone() });
            }
        }
        self.open_plugins();
    }
}
