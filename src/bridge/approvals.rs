//! Approval requests cross the trust boundary as data. Only the host's person decides.
use super::*;
use crate::bridge::store::ApprovalHistory;
use crate::model::net::DeniedDestination;
use crate::proxy::decide::Destination;
use crate::{engine::Engine, model::sandbox::SandboxName};
use enclos_protocol::approval::{Access, AccessKind, Approval};
use std::collections::HashMap;

/// Access in the spelling used by stored policy requests. Only these
/// constructors may turn a request or a logged destination into this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NormalizedAccess(Access);

impl NormalizedAccess {
    pub(super) fn new(access: &Access) -> Self {
        Self(crate::engine::normalized(access))
    }

    pub(super) fn network(
        host: &str,
        port: u16,
        private: bool,
    ) -> Result<(Self, Destination), crate::model::net::Reason> {
        use crate::net::host::{AllowEntry, HostPattern};
        if port == 0 {
            return Err(crate::model::net::Reason::BadRequest);
        }
        let destination = Destination::parse(host, port)?;
        let entry = AllowEntry {
            host: match destination.ip {
                Some(ip) => HostPattern::Ip(ip),
                None => HostPattern::Exact(destination.host.clone()),
            },
            port,
        };
        let target = match destination.ip {
            Some(ip)
                if matches!(
                    crate::net::addr::classify(ip),
                    crate::net::addr::AddrClass::Blocked(_)
                ) =>
            {
                crate::model::net::destination(&destination.host, port)
            }
            _ => entry.to_string(),
        };
        Ok((
            Self(Access {
                kind: AccessKind::Network,
                target,
                private,
            }),
            destination,
        ))
    }

    pub(super) fn as_access(&self) -> &Access {
        &self.0
    }

    /// Older network rows may predate canonical spelling. Never resolve an
    /// old writable path again: its symlinks may have changed since approval.
    pub(super) fn matches_stored(&self, stored: &Access) -> bool {
        self.as_access() == stored
            || (self.0.kind == AccessKind::Network
                && stored.kind == AccessKind::Network
                && self.0.private == stored.private
                && self.0 == crate::engine::normalized(stored))
    }

    fn legacy_spellings(
        &self,
        store: &Store,
        sandbox: &str,
        known: &[Approval],
    ) -> Result<Vec<Access>, String> {
        if self.0.kind != AccessKind::Network {
            return Ok(vec![]);
        }
        let mut spellings = Vec::new();
        let mut add = |access: Access| {
            if access != self.0 && !spellings.contains(&access) {
                spellings.push(access);
            }
        };
        for old in known {
            if old.sandbox == sandbox && self.matches_stored(&old.access) {
                add(old.access.clone());
            }
        }
        // Blocked-IP requests kept arbitrary raw spellings, including expanded
        // IPv6. Their original ids still apply outside the inbox history window.
        if let Some(destination) = request_destination(&self.0.target)
            && let Some(ip) = destination.ip
            && matches!(
                crate::net::addr::classify(ip),
                crate::net::addr::AddrClass::Blocked(_)
            )
        {
            for history in store
                .approval_history_since(sandbox, i64::MIN)
                .map_err(|e| e.to_string())?
            {
                if self.matches_stored(&history.approval.access) {
                    add(history.approval.access);
                }
            }
            if destination.port == crate::net::host::DEFAULT_PORT {
                let mut bare = self.0.clone();
                bare.target = destination.host.clone();
                add(bare);
                if ip.is_ipv6() {
                    let mut bracketed = self.0.clone();
                    bracketed.target = format!("[{}]", destination.host);
                    add(bracketed);
                }
            }
        }
        Ok(spellings)
    }

    pub(super) fn into_access(self) -> Access {
        self.0
    }
}

fn request_destination(target: &str) -> Option<Destination> {
    let (host, port) = crate::net::host::split_port(target.trim()).ok()?;
    Destination::parse(host, port).ok()
}

/// Why request `a` cannot be closed yet, if it cannot: a failed application
/// may have left a pending policy change (`pending` says whether its
/// sandbox has one), and the request is then the phone's only sign of it,
/// so it stays until the host applies or discards that change.
pub(super) fn close_blocked(a: &Approval, pending: bool) -> Option<String> {
    let name = &a.sandbox;
    (a.state == "failed" && pending).then(|| {
        format!(
            "A policy change waits on the host for {name}. Apply it with `enclos policy apply {name}` or drop it with `enclos policy discard {name}`, then close this request."
        )
    })
}

const PROBE_NOT_CLOSED: &str =
    "This is an Enclos diagnostic probe; it needs no attention and was not closed.";

/// Scope `access` of `sandbox` keyed under its active policy: a request for
/// it that was decided or closed is not asked again until the policy changes.
fn scope_key(engine: &Engine, sandbox: &str, access: &Access) -> Result<String, String> {
    let policy = sandbox
        .parse::<SandboxName>()
        .ok()
        .and_then(|n| engine.policy(&n).ok())
        .map(|v| v.snapshot.id.to_string())
        .unwrap_or_default();
    Ok(crate::policy::sha256_hex(
        format!(
            "{sandbox}:{policy}:{}",
            serde_json::to_string(access).map_err(|e| e.to_string())?
        )
        .as_bytes(),
    ))
}

fn diagnostic_access(access: &Access) -> bool {
    access.kind == AccessKind::Network
        && request_destination(&access.target)
            .is_some_and(|destination| destination.host == crate::probes::POLICY_PROBE_HOST)
}

/// The most pending requests one sandbox may have: an agent that keeps
/// asking for new targets fills neither the inbox nor the bridge's store.
pub(super) const MAX_PENDING: usize = 50;

/// Whether a proxy refusal has already been handled. Times are milliseconds:
/// pending or applying requests cover every retry for their access; completed
/// requests cover refusals at or before their recorded completion. Only a
/// strictly later millisecond can ask again, including within the same second.
/// The input type ensures different spellings share one stored form.
pub(super) fn refusal_counted(
    known: &[ApprovalHistory],
    sandbox: &str,
    access: &NormalizedAccess,
    last_ms: i64,
    since_ms: i64,
) -> bool {
    last_ms < since_ms
        || known.iter().any(|history| {
            let a = &history.approval;
            a.sandbox == sandbox
                && access.matches_stored(&a.access)
                && (matches!(a.state.as_str(), "pending" | "applying")
                    || last_ms <= history.through_ms)
        })
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

/// A sandbox's refused destinations: all of them, and those not from a
/// host diagnostic run.
pub(super) type Refusals = (Vec<DeniedDestination>, Vec<DeniedDestination>);

fn refusals(engine: &Engine, sandbox: &str) -> Option<Refusals> {
    let name = sandbox.parse::<SandboxName>().ok()?;
    Some((
        engine.net_denied(&name).ok()?,
        engine.net_denied_for_approval(&name).ok()?,
    ))
}

/// Whether `a` came from a proxy refusal, which names no agent.
fn from_the_proxy(a: &Approval) -> bool {
    a.agent.is_empty() && a.access.kind == AccessKind::Network
}

/// Whether `a`, a proxy refusal's request, was refused only in host
/// diagnostic runs.
pub(super) fn only_probe_events(a: &Approval, (all, ordinary): &Refusals) -> bool {
    if !from_the_proxy(a) {
        return false;
    }
    let Some(target) = request_destination(&a.access.target) else {
        return false;
    };
    let matches = |d: &DeniedDestination| {
        matches!(
            d.reason,
            crate::model::net::Reason::NotAllowed | crate::model::net::Reason::PrivateAddress
        ) && Destination::parse(&d.host, d.port).is_ok_and(|destination| destination == target)
    };
    all.iter().any(matches) && !ordinary.iter().any(matches)
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
        if diagnostic_access(&access) {
            return if agent.contains('/') {
                Err("This is an Enclos diagnostic probe destination, not an access request to approve.".into())
            } else {
                Ok(())
            };
        }
        // Bounds apply before storage or display. No tool arguments or output are copied.
        if access.target.is_empty()
            || access.target.len() > 4096
            || enclos_protocol::visible::has_hidden(&access.target, false)
        {
            return Err("invalid access target".into());
        }
        self.request_access_normalized(
            store,
            agent,
            conversation,
            NormalizedAccess::new(&access),
            action,
        )
    }

    fn request_access_normalized(
        &self,
        store: &Store,
        agent: &str,
        conversation: Option<&str>,
        normalized: NormalizedAccess,
        action: &str,
    ) -> Result<(), String> {
        let sandbox = agent.split('/').next().unwrap_or(agent);
        let access = normalized.as_access();
        let open = store.approvals().map_err(|e| e.to_string())?;
        // A request for a scope already open adds nothing: no cap. A proxy's
        // becomes the agent's explicit one, as #209 does.
        if let Some(mut existing) = open
            .iter()
            .find(|a| {
                a.sandbox == sandbox
                    && normalized.matches_stored(&a.access)
                    && (a.state == "pending" || a.state == "applying")
            })
            .cloned()
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
                    return self.request_access_normalized(
                        store,
                        agent,
                        conversation,
                        normalized,
                        action,
                    );
                }
                if let Some(person) = self.known_host() {
                    self.deliver(&person, ToDevice::Approval(existing));
                    self.publish_open_items(store, &person);
                }
            }
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
        let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
        let mut key = scope_key(&engine, sandbox, access)?;
        // Decided or closed under this policy: not asked again until it
        // changes. An agent is told so, not left waiting for a request
        // nobody sees. A failed request may be reopened by an explicit agent
        // request, or by a proxy refusal after that failure was recorded.
        let known = |state: &str| {
            if agent.contains('/') && !matches!(state, "pending" | "applying") {
                Err(format!(
                    "A request for this scope was already {state} under {sandbox}'s active policy. It is not asked again until the policy changes."
                ))
            } else {
                Ok(())
            }
        };
        // Closed under this policy, though it may have been asked under an
        // earlier one, whose id this key is not.
        let mut scope_keys = vec![key.clone()];
        for old in normalized.legacy_spellings(store, sandbox, &open)? {
            let old_key = scope_key(&engine, sandbox, &old)?;
            if !scope_keys.contains(&old_key) {
                scope_keys.push(old_key);
            }
        }
        for scope in &scope_keys {
            if store.scope_closed(scope).map_err(|e| e.to_string())? {
                return known("closed");
            }
        }
        let mut old = None;
        for scope in scope_keys {
            if let Some(stored) = store.approval(&scope).map_err(|e| e.to_string())? {
                key = scope;
                old = Some(stored);
                break;
            }
        }
        if old.as_ref().is_some_and(|k| k.state == "diagnostic") {
            // A later genuine attempt gets a new id; stale decisions for the test stay closed.
            key = crate::policy::sha256_hex(format!("{key}:after-diagnostic").as_bytes());
            old = store.approval(&key).map_err(|e| e.to_string())?;
        }
        // A legacy id was hashed from its original access. Keep that spelling
        // on a reopened row so later lookups can still recover the same id.
        let reopened_access = old
            .as_ref()
            .filter(|k| k.state == "failed")
            .map(|k| k.access.clone());
        let reopen = reopened_access.is_some();
        if let Some(old) = old.filter(|_| !reopen) {
            return known(&old.state);
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
            access: reopened_access.unwrap_or_else(|| normalized.into_access()),
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
        preview(&engine, &mut a);
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
            self.publish_open_items(store, &person);
        }
        Ok(())
    }

    /// Whether `a` is a pending request for a diagnostic probe's refusal.
    /// `read` keeps each sandbox's refusals, so that one pass over the
    /// requests reads the network log twice per sandbox, not per request.
    fn is_probe(&self, a: &Approval, read: &mut HashMap<String, Option<Refusals>>) -> bool {
        a.state == "pending"
            && (diagnostic_access(&a.access)
                || (from_the_proxy(a)
                    && read
                        .entry(a.sandbox.clone())
                        .or_insert_with(|| {
                            refusals(
                                &Engine::open(self.layout.clone(), crate::state::Wait::Background),
                                &a.sandbox,
                            )
                        })
                        .as_ref()
                        .is_some_and(|r| only_probe_events(a, r))))
    }

    pub(super) fn dismiss_probe_requests(&self, store: &Store) -> Result<(), String> {
        let mut read = HashMap::new();
        for a in store.approvals().map_err(|e| e.to_string())? {
            if self.is_probe(&a, &mut read)
                && let Some(closed) = store.dismiss_probe(&a).map_err(|e| e.to_string())?
                && let Some(person) = self.known_host()
            {
                self.deliver(&person, ToDevice::Approval(closed));
                self.publish_open_items(store, &person);
            }
        }
        Ok(())
    }

    /// Turns the proxies' recent refusals into policy requests. A refusal
    /// counts once: pending and applying requests cover their retries, and
    /// completion covers every refusal at or before its millisecond cutoff.
    /// A later policy change alone cannot ask again; a later refusal can.
    pub(super) fn collect_refusals(&self, store: &Store) -> Result<(), String> {
        self.dismiss_probe_requests(store)?;
        let since = store
            .refusals_since()
            .map_err(|e| e.to_string())?
            .saturating_mul(1000);
        let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
        let agents = self.agents();
        let sandboxes: std::collections::HashSet<_> = agents
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
                .and_then(|view| Ok((view.snapshot.policy, engine.net_denied_for_approval(&name)?)))
            {
                Ok(read) => read,
                Err(e) => {
                    eprintln!("enclos app approvals: {sandbox}: {e}");
                    continue;
                }
            };
            let denied: Vec<_> = denied.into_iter().take(200).collect();
            // Only the requests a refusal still to be counted can match:
            // this sandbox's waiting requests or completions covering that time.
            let Some(from) = denied
                .iter()
                .map(|d| d.last.as_millisecond())
                .filter(|&last| last >= since)
                .min()
            else {
                continue;
            };
            let known = match store.approval_history_since(sandbox, from) {
                Ok(known) => known,
                Err(e) => {
                    eprintln!("enclos app approvals: {sandbox}: {e}");
                    continue;
                }
            };
            for d in denied {
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
                let private = d.reason == Reason::PrivateAddress;
                let Ok((access, destination)) = NormalizedAccess::network(&d.host, d.port, private)
                else {
                    continue;
                };
                if refusal_counted(&known, sandbox, &access, d.last.as_millisecond(), since) {
                    continue;
                }
                let allowed = crate::proxy::decide::allowed(&policy, &destination);
                if allowed
                    && (d.reason != Reason::PrivateAddress
                        || policy.net.private.contains(&destination.host))
                {
                    continue;
                }
                // The log is sandbox-wide: do not invent a requesting agent or conversation.
                let action = format!("Connect to {}", access.as_access().target);
                self.request_access_normalized(store, sandbox, None, access, &action)?;
            }
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
        self.host_authority(store, device, person)
            .map_err(|(_, message)| message)?;
        let read = || -> Result<Approval, String> {
            Ok(store
                .approval(id)
                .map_err(|e| e.to_string())?
                .ok_or("Unknown policy request")?)
        };
        let mut a = read()?;
        // As a decision would: a probe's refusal is marked as one, not closed.
        if self.is_probe(&a, &mut HashMap::new()) {
            if let Some(marked) = store.dismiss_probe(&a).map_err(|e| e.to_string())? {
                self.deliver(person, ToDevice::Approval(marked));
                self.publish_open_items(store, person);
            }
            return Err(PROBE_NOT_CLOSED.into());
        }
        let engine = Engine::open(self.layout.clone(), crate::state::Wait::Background);
        // Closed under the policy active now too, which the request's id,
        // made under the policy of its time, may not name.
        let scope = scope_key(&engine, &a.sandbox, &a.access)?;
        // Closed from one reading of its state. A request that changed
        // since, such as an application that failed after it was read, is
        // read and checked again; states only move forward, so this ends.
        for _ in 0..3 {
            if !matches!(a.state.as_str(), "pending" | "failed") {
                break;
            }
            if self.close_from(&engine, store, &a, &scope, device, person)? {
                a.state = "closed".into();
                break;
            }
            a = read()?;
        }
        let state = a.state.clone();
        self.deliver(person, ToDevice::Approval(a));
        self.publish_open_items(store, person);
        match state.as_str() {
            "closed" => Ok(()),
            "applying" => Err(
                "This request is already being decided. Wait for the result before closing it."
                    .into(),
            ),
            "pending" | "failed" => {
                Err("This request kept changing while it was being closed. Try again.".into())
            }
            "diagnostic" => Err(PROBE_NOT_CLOSED.into()),
            decided => Err(format!(
                "This request was already {decided}, so it was not closed."
            )),
        }
    }

    /// Closes `a` from the state it was read in, `pending` or `failed`. A
    /// failed one is checked and closed under the state lock, so that no
    /// pending policy change appears in between; a pending change that
    /// cannot be read keeps it.
    fn close_from(
        &self,
        engine: &Engine,
        store: &Store,
        a: &Approval,
        scope: &str,
        device: &Device,
        person: &str,
    ) -> Result<bool, String> {
        // The store transition also checks the state atomically against other devices.
        let close = || {
            store
                .close_approval(&a.request, &a.state, scope, &device.id, person)
                .map_err(|e| e.to_string())
        };
        let (true, Ok(name)) = (a.state == "failed", a.sandbox.parse::<SandboxName>()) else {
            return close();
        };
        engine
            .with_pending_policy(&name, |pending| match close_blocked(a, pending) {
                Some(why) => Err(why),
                None => close(),
            })
            .map_err(|e| {
                format!(
                    "Enclos could not check {name} for a pending policy change, so this request stays. Check it with `enclos policy show {name}`: {e}"
                )
            })?
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
        self.host_authority(store, device, person)
            .map_err(|(_, message)| message)?;
        let mut a = store
            .approval(id)
            .map_err(|e| e.to_string())?
            .ok_or("Unknown policy request")?;
        if self.is_probe(&a, &mut HashMap::new()) {
            if let Some(closed) = store.dismiss_probe(&a).map_err(|e| e.to_string())? {
                self.deliver(person, ToDevice::Approval(closed));
                self.publish_open_items(store, person);
            }
            return Err("This is an Enclos diagnostic probe; no approval is needed.".into());
        }
        if a.state != "pending" {
            self.deliver(person, ToDevice::Approval(a));
            self.publish_open_items(store, person);
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
                self.publish_open_items(store, person);
                return Err("The policy changed or this scope cannot be approved. Review the request's current details.".into());
            }
        }
        if !store.claim_approval(id).map_err(|e| e.to_string())? {
            return Err("This request is already being decided on another device.".into());
        }
        a.state = "applying".into();
        self.deliver(person, ToDevice::Approval(a.clone()));
        self.publish_open_items(store, person);
        let by = super::authority::device_actor(person, &device.id, Some(id));
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
        self.publish_open_items(store, person);
        // Knowledge is the active policy, never a speculative grant from a button press.
        self.refresh_access_context(&a.sandbox);
        Ok(())
    }

    pub(super) fn refresh_access_context(self: &Arc<Self>, sandbox: &str) {
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

#[cfg(test)]
mod normalization_tests {
    use super::*;

    #[test]
    fn explicit_requests_and_logged_destinations_share_one_spelling() {
        for (raw, host, port, target, canonical_host) in [
            (
                "API.EXAMPLE.COM.:443",
                "API.EXAMPLE.COM.",
                443,
                "api.example.com",
                "api.example.com",
            ),
            (
                "api.example.com:8443",
                "api.example.com",
                8443,
                "api.example.com:8443",
                "api.example.com",
            ),
            (
                "[FC00:0000:0:0:0:0:0:1]:443",
                "FC00:0000:0:0:0:0:0:1",
                443,
                "fc00::1",
                "fc00::1",
            ),
            (
                "[fc00::1]:8443",
                "[FC00:0000:0:0:0:0:0:1]",
                8443,
                "[fc00::1]:8443",
                "fc00::1",
            ),
            ("127.0.0.1", "127.0.0.1", 443, "127.0.0.1:443", "127.0.0.1"),
            ("[0:0:0:0:0:0:0:1]", "[::1]", 443, "[::1]:443", "::1"),
            (
                "169.254.169.254:8443",
                "169.254.169.254",
                8443,
                "169.254.169.254:8443",
                "169.254.169.254",
            ),
        ] {
            for private in [false, true] {
                let explicit = NormalizedAccess::new(&Access {
                    kind: AccessKind::Network,
                    target: raw.into(),
                    private,
                });
                let (collected, destination) =
                    NormalizedAccess::network(host, port, private).unwrap();
                assert_eq!(explicit, collected, "{raw}, {host}:{port}");
                assert_eq!(collected.as_access().target, target);
                assert_eq!(collected.as_access().private, private);
                assert_eq!(destination.host, canonical_host);
                assert_eq!(destination.port, port);
            }
        }
    }

    #[test]
    fn historical_network_spellings_match_without_resolving_old_write_paths() {
        let (network, _) = NormalizedAccess::network("127.0.0.1", 443, false).unwrap();
        let mut stored = Access {
            kind: AccessKind::Network,
            target: "127.0.0.1".into(),
            private: false,
        };
        assert!(network.matches_stored(&stored));
        stored.private = true;
        assert!(!network.matches_stored(&stored));
        stored.private = false;
        stored.target = "127.0.0.1:8443".into();
        assert!(!network.matches_stored(&stored));

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let alias = dir.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let mut stored = Access {
            kind: AccessKind::Write,
            target: real.display().to_string(),
            private: false,
        };
        let current = NormalizedAccess::new(&stored);
        stored.target = alias.display().to_string();
        assert!(!current.matches_stored(&stored));
    }

    #[test]
    fn invalid_logged_destinations_cannot_become_normalized_network_access() {
        for host in ["", "localhost", "*.example.com", "not a host"] {
            assert_eq!(
                NormalizedAccess::network(host, 443, false).unwrap_err(),
                crate::model::net::Reason::BadRequest
            );
        }
        assert_eq!(
            NormalizedAccess::network("example.com", 0, false).unwrap_err(),
            crate::model::net::Reason::BadRequest
        );
    }
}
