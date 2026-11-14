//! The bridge's side of group conversations (ADR 0045, proposed;
//! `docs/protocol.md`, Groups): the discussions it runs, what a member's
//! messages do to them, and the person's `group.new` and `group.stop`. The
//! rules themselves, without I/O, are in `bridge::groups`.

#[cfg(test)]
#[path = "group_turns_tests.rs"]
mod tests;

use super::*;

impl Hub {
    /// The person said `text` (message `seq`) in group `id`: a discussion
    /// starts, or waits for the running turn.
    pub(super) fn group_said(self: &Arc<Hub>, store: &Store, id: &str, seq: i64, text: &str) {
        if store.deletion_started(id).unwrap_or(true) {
            return;
        }
        let Some((_, handles)) = group_of(store, id) else {
            return;
        };
        {
            let mut groups = self.groups.lock().expect("not poisoned");
            match groups.get_mut(id) {
                Some(d) if d.running.is_some() => d.wait_for(seq, text),
                _ => {
                    groups.insert(id.to_owned(), Discussion::new(seq, text, &handles));
                }
            }
        }
        self.advance(store, id);
    }

    /// Starts group `id`'s next turn, if one is due: the member is sent the
    /// group's messages it has not seen, under the group's id. A member
    /// that cannot be reached fails its turn, and the next goes on.
    pub(super) fn advance(self: &Arc<Hub>, store: &Store, id: &str) {
        if store.deletion_started(id).unwrap_or(true) {
            return;
        }
        let Some((sandbox, handles)) = group_of(store, id) else {
            return;
        };
        let owner = store.owner(id).ok().flatten().unwrap_or_default();
        let title = store
            .conversation_info(id)
            .ok()
            .flatten()
            .and_then(|c| c.title)
            .unwrap_or_else(|| handles.join(", "));
        loop {
            let seen: HashMap<String, i64> =
                store.members(id).unwrap_or_default().into_iter().collect();
            let position = |m: &str| seen.get(m).copied().unwrap_or(0);
            // A member has something to be given when another's words came
            // after the last message it was given: its own reply does not
            // count, and its position never passes a message it was not
            // given, such as the person's sent while its turn ran.
            let fresh: HashSet<&str> = handles
                .iter()
                .map(String::as_str)
                .filter(|m| store.news_for(id, m, position(m)).unwrap_or(false))
                .collect();
            let sent = match new_id()
                .map_err(|e| e.to_string())
                .and_then(|i| MessageId::new(i).map_err(|e| e.to_string()))
            {
                Ok(sent) => sent,
                Err(e) => return eprintln!("enclos app: group {id}: {e}"),
            };
            let mut groups = self.groups.lock().expect("not poisoned");
            let Some(d) = groups.get_mut(id) else { return };
            // A newer message of the person's waited for the turn that ran.
            if d.running.is_none()
                && let Some((seq, text)) = d.pending.take()
            {
                *d = Discussion::new(seq, &text, &handles);
            }
            let next = d.next_turn(&handles, |m| fresh.contains(m));
            let Some((member, direct)) = next else {
                drop(groups);
                self.deliver_group_state(store, id);
                return;
            };
            let (source, round) = (d.source, d.round);
            let turn = turn_id(id, source, round, &member);
            // What the member is given: the messages after its position,
            // the newest that a prompt holds and one more, which tells it
            // that earlier ones were left out; its position then moves to
            // the last of them, and no further.
            let unseen = store
                .newest_after(id, position(&member), crate::bridge::groups::MAX_UNSEEN + 1)
                .unwrap_or_default();
            let given = unseen.last().map_or(position(&member), |m| m.seq);
            // Running before it is sent, under the lock: a second call (the
            // person's new message as a reply lands) finds the group busy
            // instead of sending a turn of its own, and the member's reply
            // cannot come before the bridge knows what it answers.
            d.started(
                &member,
                turn.clone(),
                sent.as_str().to_owned(),
                given,
                direct,
            );
            let _ = store.turn(
                &turn,
                id,
                source,
                round,
                &member,
                "running",
                Some(sent.as_str()),
                Some(given),
                None,
            );
            drop(groups);
            self.deliver_group_state(store, id);
            let own = From::Member(member.clone());
            let said: Vec<Said> = unseen
                .iter()
                .filter(|m| m.kind != "status" && m.from != own)
                .map(|m| Said {
                    member: match &m.from {
                        From::Member(a) => Some(a.as_str()),
                        _ => None,
                    },
                    person: match &m.from {
                        From::Person(p) => p.split('@').next().unwrap_or(p),
                        _ => "",
                    },
                    text: &m.text,
                })
                .collect();
            let others: Vec<String> = handles.iter().filter(|h| **h != member).cloned().collect();
            let text = prompt(&title, &member, &others, &said, direct);
            if !self.runs(id, &turn) {
                return; // stopped meanwhile
            }
            match self.send_to(&format!("{sandbox}/{member}"), id, &owner, &sent, &text) {
                Ok(()) => {
                    let _ = store.saw(id, &member, given);
                    return;
                }
                Err(e) => {
                    let mut groups = self.groups.lock().expect("not poisoned");
                    match groups.get_mut(id) {
                        Some(d) if d.running.as_ref().is_some_and(|r| r.turn == turn) => {
                            d.failed();
                        }
                        _ => return,
                    }
                    drop(groups);
                    let _ = store.turn_status(&turn, "failed", Some(&e));
                }
            }
        }
    }

    /// `member`'s reply to plugin message `sent`, which ended its turn in
    /// group `id`, was `stored` or not. Stored, the turn is replied. Not
    /// stored (the database failed), the turn failed, as if no reply came:
    /// the plugin sends the reply again, which is then kept as a reply to
    /// a failed turn, and not dropped as one to a turn replied already.
    pub(super) fn turn_replied(
        &self,
        store: &Store,
        id: &str,
        member: &str,
        sent: Option<&str>,
        stored: bool,
    ) {
        let Some(sent) = sent else { return };
        let Ok(Some((turn, _, _))) = store.turn_sent(sent, id, member) else {
            return;
        };
        if stored {
            let _ = store.turn_status(&turn, "replied", None);
            return;
        }
        let _ = store.turn_status(&turn, "failed", Some("its reply could not be stored"));
        // group.state says so when the next turn starts (`advance`)
        if let Some(d) = self.groups.lock().expect("not poisoned").get_mut(id)
            && d.turns.get(member).is_some_and(|t| t == "replied")
        {
            d.turns.insert(member.to_owned(), "failed".to_owned());
        }
    }

    /// Whether `turn` is group `id`'s running turn.
    fn runs(&self, id: &str, turn: &str) -> bool {
        self.groups
            .lock()
            .expect("not poisoned")
            .get(id)
            .and_then(|d| d.running.as_ref())
            .is_some_and(|r| r.turn == turn)
    }

    /// A message of `member`'s to group `id`, with `files` when it carries
    /// any: `Some(true)` for the reply that ends its running turn, to keep,
    /// then go on; `Some(false)` for one to keep (what it says before its
    /// reply, or on its own); `None` for one to drop (a pass, or the reply
    /// to a turn that was stopped).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn group_reply(
        self: &Arc<Hub>,
        store: &Store,
        id: &str,
        member: &str,
        reply_to: Option<&str>,
        text: &str,
        files: bool,
        kind: &str,
    ) -> Option<bool> {
        let (_, handles) = group_of(store, id)?;
        let mut groups = self.groups.lock().expect("not poisoned");
        if let Some(d) = groups.get_mut(id)
            && let Some(run) = &d.running
            && run.member == member
            && reply_to == Some(run.sent.as_str())
        {
            let turn = run.turn.clone();
            let ended = d.replied(text, files, &handles);
            drop(groups);
            return match ended {
                // Recorded replied once the reply is stored (`turn_replied`)
                Ended::Replied => Some(true),
                Ended::Passed => {
                    let _ = store.turn_status(&turn, "passed", None);
                    self.advance(store, id);
                    None
                }
                Ended::Failed(why) => {
                    let _ = store.turn_status(&turn, "failed", Some(&why));
                    self.advance(store, id);
                    None
                }
            };
        }
        drop(groups);
        // The runtime's answer to the bridge's /stop: the "Stopped" line says it.
        if reply_to.is_some_and(|r| self.stops.lock().expect("not poisoned").remove(r)) {
            return None;
        }
        // A reply to no running turn of its: kept only when its own turn
        // in this group failed because the bridge restarted (the plugin
        // sent it again since).
        if kind == "reply"
            && let Some(sent) = reply_to
        {
            return match store.turn_sent(sent, id, member) {
                Ok(Some((turn, status, _))) if status == "failed" => {
                    let _ = store.turn_status(&turn, "replied", None);
                    Some(false)
                }
                Ok(Some(_)) => None,
                // Not a turn's: the member answered on its own.
                _ => Some(false),
            };
        }
        Some(false)
    }

    /// The person stopped group `id`'s discussion: what is queued is
    /// cancelled, and the running member is sent `/stop`.
    pub(super) fn group_stop(self: &Arc<Hub>, store: &Store, id: &str) {
        let Some((sandbox, _)) = group_of(store, id) else {
            return;
        };
        let running = self
            .groups
            .lock()
            .expect("not poisoned")
            .get_mut(id)
            .and_then(Discussion::stop);
        if let Some(run) = running {
            let _ = store.turn_status(&run.turn, "cancelled", None);
            let owner = store.owner(id).ok().flatten().unwrap_or_default();
            if let Ok(sent) = new_id()
                .map_err(|e| e.to_string())
                .and_then(|i| MessageId::new(i).map_err(|e| e.to_string()))
            {
                // Known before it is sent, so the runtime's answer is.
                self.stops
                    .lock()
                    .expect("not poisoned")
                    .insert(sent.as_str().to_owned());
                let agent = format!("{sandbox}/{}", run.member);
                if self.send_to(&agent, id, &owner, &sent, "/stop").is_err() {
                    self.stops
                        .lock()
                        .expect("not poisoned")
                        .remove(sent.as_str());
                }
            }
        }
        self.deliver_group_state(store, id);
    }

    /// Fails the turns that ran longer than [`TURN_TIMEOUT`], and goes on.
    pub(super) fn expire_turns(self: &Arc<Hub>, store: &Store) {
        let late: Vec<(String, String)> = self
            .groups
            .lock()
            .expect("not poisoned")
            .iter_mut()
            .filter_map(|(id, d)| {
                let run = d
                    .running
                    .as_ref()
                    .filter(|r| r.started.elapsed() > TURN_TIMEOUT)?;
                let turn = run.turn.clone();
                d.failed();
                Some((id.clone(), turn))
            })
            .collect();
        for (id, turn) in late {
            let _ = store.turn_status(&turn, "failed", Some("no reply in 15 minutes"));
            self.advance(store, &id);
        }
    }

    /// Fails the running turns of `agent` (`sandbox/agent`), and goes on:
    /// the one sent as plugin message `sent`, which its plugin answered
    /// with an `error`, or, with no `sent`, every one, its plugin
    /// connection closed. Waiting for [`TURN_TIMEOUT`] would hold the
    /// group for nothing.
    pub(super) fn fail_turns(
        self: &Arc<Hub>,
        store: &Store,
        agent: &str,
        sent: Option<&str>,
        why: &str,
    ) {
        let Some((sandbox, member)) = agent.split_once('/') else {
            return;
        };
        let failed: Vec<(String, String)> = self
            .groups
            .lock()
            .expect("not poisoned")
            .iter_mut()
            .filter_map(|(id, d)| {
                let run = d.running.as_ref()?;
                if run.member != member || sent.is_some_and(|s| s != run.sent) {
                    return None;
                }
                if !matches!(group_of(store, id), Some((s, _)) if s == sandbox) {
                    return None;
                }
                let turn = run.turn.clone();
                d.failed();
                Some((id.clone(), turn))
            })
            .collect();
        for (id, turn) in failed {
            let _ = store.turn_status(&turn, "failed", Some(why));
            self.advance(store, &id);
        }
    }

    /// The turns left running when the bridge stopped: failed, and their
    /// discussions ended, which `group.state` says; the person's next
    /// message starts a new one (ADR 0045).
    pub(super) fn restarted(&self, store: &Store) {
        let mut groups = self.groups.lock().expect("not poisoned");
        for (turn, conversation, member) in store.running_turns().unwrap_or_default() {
            let _ = store.turn_status(&turn, "failed", Some("the bridge restarted"));
            groups.insert(conversation, Discussion::interrupted(&member));
        }
    }

    /// Where group `id`'s discussion is; settled, with no turns, before the first.
    pub(super) fn group_state(&self, store: &Store, id: &str) -> Option<GroupState> {
        let (sandbox, handles) = group_of(store, id)?;
        let groups = self.groups.lock().expect("not poisoned");
        let d = groups.get(id);
        Some(GroupState {
            conversation: ConversationId::new(id).ok()?,
            state: d.map_or("settled".to_owned(), |d| d.state.clone()),
            round: d.map_or(0, |d| d.round),
            max_rounds: MAX_ROUNDS,
            members: handles
                .iter()
                .map(|h| MemberTurn {
                    agent: format!("{sandbox}/{h}"),
                    turn: d.and_then(|d| d.turns.get(h).cloned()),
                })
                .collect(),
            reason: d.and_then(|d| d.reason.clone()),
        })
    }

    /// Sends where group `id`'s discussion is to its owner's devices.
    pub(super) fn deliver_group_state(&self, store: &Store, id: &str) {
        if let (Some(state), Ok(Some(owner))) = (self.group_state(store, id), store.owner(id)) {
            self.deliver(&owner, ToDevice::GroupState(state));
        }
    }

    /// Sends `text` to `agent`'s plugin as `person`'s message in
    /// `conversation`, as plugin message `sent`, opening the plugin
    /// connection if it is not.
    fn send_to(
        self: &Arc<Hub>,
        agent: &str,
        conversation: &str,
        person: &str,
        sent: &MessageId,
        text: &str,
    ) -> Result<(), String> {
        self.plugin(agent)?;
        let conversation = ConversationId::new(conversation).map_err(|e| e.to_string())?;
        let person = Person::new(person).map_err(|e| e.to_string())?;
        // Written outside the plugins lock, through the plugin's own
        let out = {
            let plugins = self.plugins.lock().expect("not poisoned");
            let plugin = plugins
                .get(agent)
                .ok_or_else(|| format!("{agent}'s app channel closed"))?;
            Arc::clone(&plugin.out)
        };
        let host = self.known_host().as_deref() == Some(person.as_str());
        let mut out = out.lock().expect("not poisoned");
        if text != "/stop"
            && self
                .store()?
                .deletion_started(conversation.as_str())
                .map_err(|e| e.to_string())?
        {
            return Err("This conversation is being deleted.".into());
        }
        out.writer
            .send_as(
                sent,
                FromBridge::MessageIn {
                    conversation,
                    person,
                    text: text.to_owned(),
                    host: Some(host),
                },
            )
            .map_err(|e| e.to_string())
    }
}

/// The person's `group.new`: two to six known agents of one sandbox, each
/// once, under an id no conversation has (ADR 0045). The same request
/// again, after an answer that was lost, is answered with the group as it
/// is. `Ok(Err(why))` for a request refused, to say to the device; `Err`
/// for the bridge's database failing.
pub(super) fn new_group(
    hub: &Hub,
    store: &Store,
    person: &str,
    id: &str,
    members: &[String],
    title: Option<String>,
) -> Result<Result<(), String>, String> {
    let mut sandbox = None;
    let mut names: Vec<String> = Vec::new();
    for m in members {
        let Some((s, n)) = m.split_once('/') else {
            continue;
        };
        if hub.agents.iter().any(|a| &a.name == m)
            && sandbox.get_or_insert(s.to_owned()) == s
            && !names.iter().any(|x| x == n)
        {
            names.push(n.to_owned());
        }
    }
    let shape = format!(
        "a group has {MIN_MEMBERS} to {MAX_MEMBERS} known agents of one sandbox, each once"
    );
    let Some(sandbox) = sandbox else {
        return Ok(Err(shape));
    };
    if names.len() != members.len() || !(MIN_MEMBERS..=MAX_MEMBERS).contains(&names.len()) {
        return Ok(Err(shape));
    }
    if is_home(id) {
        return Ok(Err("a group cannot have a Home's id".to_owned()));
    }
    if let Some((s, agent, owner)) = store.conversation_of(id).map_err(|e| e.to_string())? {
        let same = owner == person
            && agent.is_empty()
            && s == sandbox
            && group_of(store, id).is_some_and(|(_, handles)| handles == names);
        if !same {
            return Ok(Err(format!("conversation {id} exists already")));
        }
    } else {
        // Made meanwhile by another `group.new` with this id: theirs
        let (owner, made) = store
            .group(id, &sandbox, &names, person)
            .map_err(|e| e.to_string())?;
        if owner != person || made != names {
            return Ok(Err(format!("conversation {id} exists already")));
        }
        let name = title
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| names.join(", "));
        store
            .name(id, &name, BY_PERSON)
            .map_err(|e| e.to_string())?;
    }
    hub.deliver_conversation(store, person, id);
    hub.deliver_group_state(store, id);
    Ok(Ok(()))
}

/// The person's `group.stop`: only the group's owner stops it.
pub(super) fn stop_group(
    hub: &Arc<Hub>,
    store: &Store,
    person: &str,
    id: &str,
) -> Result<(), String> {
    if store.owner(id).map_err(|e| e.to_string())?.as_deref() == Some(person) {
        hub.group_stop(store, id);
    }
    Ok(())
}
