//! Tasks and agent activity, as an agent's plugin reports them
//! (`docs/protocol.md`, Tasks and agent activity; ADR 0068, proposed):
//! checked against the connection, cleaned, kept and passed on.
use super::*;
use enclos_protocol::task::{Activity, Task};

/// Why a reported task is not kept.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TaskRefusal {
    /// The plugin is answered `bad_message`, and the task acknowledged: it
    /// would be refused again.
    Bad(String),
    /// The bridge's database failed: not acknowledged, and the connection
    /// ends, so the plugin sends its list again.
    Store(String),
}

impl Hub {
    /// Records what `agent` (`<sandbox>/<agent>`) is doing, as the plugin
    /// connection `generation` reported it, and tells each connected device
    /// what its person may see of it, when that changed. A report from a
    /// connection older than the one the bridge holds is not taken.
    pub(super) fn set_activity(
        &self,
        store: Option<&Store>,
        agent: &str,
        generation: u64,
        activity: Activity,
    ) {
        let before = {
            let mut current = self.activity.lock().expect("not poisoned");
            if current.get(agent).is_some_and(|(g, _)| *g > generation) {
                return;
            }
            let before = if activity.idle() {
                current.remove(agent)
            } else {
                current.insert(agent.to_owned(), (generation, activity.clone()))
            }
            .map(|(_, a)| a)
            .unwrap_or_default();
            if before == activity {
                return;
            }
            before
        };
        self.activity_changed(store, agent, &before, &activity);
    }

    /// Makes `agent` idle when the activity the bridge holds is the one
    /// connection `generation` reported: that connection closed, however
    /// it closed, and no plugin is left to say the agent stopped.
    pub(super) fn end_activity(&self, store: Option<&Store>, agent: &str, generation: u64) {
        let before = {
            let mut current = self.activity.lock().expect("not poisoned");
            if current.get(agent).is_none_or(|(g, _)| *g != generation) {
                return;
            }
            current.remove(agent).map(|(_, a)| a).unwrap_or_default()
        };
        self.activity_changed(store, agent, &before, &Activity::default());
    }

    /// Records `agent`'s new activity for `enclos status`, and sends each
    /// person who sees the agent what they may see of it, when that part
    /// changed: a guest learns nothing of the host's view changing.
    fn activity_changed(
        &self,
        store: Option<&Store>,
        agent: &str,
        before: &Activity,
        after: &Activity,
    ) {
        if let Some(store) = store
            && let Err(e) = store.set_activity(agent, after)
        {
            eprintln!("enclos app: {agent}: cannot record its activity: {e}");
        }
        let host = self.known_host();
        let people: HashSet<String> = self
            .devices
            .lock()
            .expect("not poisoned")
            .values()
            .map(|(person, _, _)| person.clone())
            .collect();
        for person in people {
            if !self.sees_agent(&person, agent) {
                continue;
            }
            let seen = seen_by(store, after, host.as_deref(), &person);
            if seen == seen_by(store, before, host.as_deref(), &person) {
                continue;
            }
            self.deliver(
                &person,
                ToDevice::AgentActivity {
                    agent: agent.to_owned(),
                    activity: seen,
                },
            );
        }
    }

    /// Drops what the bridge keeps of `agent`'s tasks: its plugin no longer
    /// reports them.
    pub(super) fn tasks_unreported(&self, store: &Store, agent: &str) {
        let (sandbox, _) = agent.split_once('/').unwrap_or((agent, ""));
        match store.replace_tasks(sandbox, agent, &[], now()) {
            Ok(changes) => {
                let host = store.host_person().ok().flatten();
                self.deliver_tasks(host.as_deref(), &changes);
            }
            Err(e) => {
                eprintln!("enclos app: {agent}: cannot drop the tasks it no longer reports: {e}")
            }
        }
    }

    /// What `person` is sent after `agents.list`: the activity of each
    /// agent they are shown that is not idle, as they may see it.
    pub(super) fn activities_for(&self, store: &Store, person: &str) -> Vec<ToDevice> {
        let host = self.known_host();
        let current: Vec<(String, Activity)> = self
            .activity
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(agent, (_, activity))| (agent.clone(), activity.clone()))
            .collect();
        let mut out: Vec<ToDevice> = current
            .into_iter()
            .filter(|(agent, _)| self.sees_agent(person, agent))
            .map(|(agent, activity)| {
                (
                    agent,
                    seen_by(Some(store), &activity, host.as_deref(), person),
                )
            })
            .filter(|(_, seen)| !seen.idle())
            .map(|(agent, activity)| ToDevice::AgentActivity { agent, activity })
            .collect();
        out.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        out
    }

    /// Keeps a task `agent`'s plugin reported, and passes on what changed.
    pub(super) fn task_reported(
        &self,
        store: &Store,
        agent: &str,
        task: Task,
    ) -> Result<(), TaskRefusal> {
        let (sandbox, _) = agent.split_once('/').unwrap_or((agent, ""));
        let host = store
            .host_person()
            .map_err(|e| TaskRefusal::Store(e.to_string()))?;
        let task = kept_form(store, agent, host.as_deref(), task, now())?;
        let changes = store
            .put_task(sandbox, &task, now())
            .map_err(|e| TaskRefusal::Store(e.to_string()))?;
        self.deliver_tasks(host.as_deref(), &changes);
        if changes.full > 0 {
            return Err(TaskRefusal::Bad(full()));
        }
        Ok(())
    }

    /// Makes what the bridge keeps of `agent`'s tasks the list its plugin
    /// sent. A task in it the bridge refuses is left out; the answer counts
    /// them and gives the first one's reason.
    pub(super) fn tasks_reported(
        &self,
        store: &Store,
        agent: &str,
        tasks: Vec<Task>,
    ) -> Result<(), TaskRefusal> {
        let (sandbox, _) = agent.split_once('/').unwrap_or((agent, ""));
        let host = store
            .host_person()
            .map_err(|e| TaskRefusal::Store(e.to_string()))?;
        let at = now();
        let mut kept = Vec::new();
        let mut refused = Vec::new();
        for task in tasks.into_iter().take(enclos_protocol::task::MAX_TASKS) {
            match kept_form(store, agent, host.as_deref(), task, at) {
                Ok(task) => kept.push(task),
                Err(TaskRefusal::Bad(why)) => refused.push(why),
                Err(e) => return Err(e),
            }
        }
        let changes = store
            .replace_tasks(sandbox, agent, &kept, at)
            .map_err(|e| TaskRefusal::Store(e.to_string()))?;
        self.deliver_tasks(host.as_deref(), &changes);
        if changes.full > 0 {
            refused.push(full());
        }
        match refused.first() {
            Some(first) => Err(TaskRefusal::Bad(format!(
                "{} of the tasks were refused; the first: {first}",
                refused.len()
            ))),
            None => Ok(()),
        }
    }

    /// The kept tasks, for a sync of the host's person; the ones that
    /// passed their 3 days meanwhile are dropped, and the host's person's
    /// devices told.
    pub(super) fn tasks_for_sync(&self, store: &Store, host: &str) -> Result<Vec<Task>, String> {
        let (tasks, removed) = store.tasks(now()).map_err(|e| e.to_string())?;
        self.deliver_tasks(
            Some(host),
            &crate::bridge::store::TaskChanges {
                removed,
                ..Default::default()
            },
        );
        Ok(tasks)
    }

    /// Tells the host's person's devices what storing tasks changed.
    fn deliver_tasks(&self, host: Option<&str>, changes: &crate::bridge::store::TaskChanges) {
        let Some(host) = host else {
            return;
        };
        for key in &changes.removed {
            self.deliver(
                host,
                ToDevice::TaskRemoved {
                    agent: key.agent.clone(),
                    task: key.task.clone(),
                },
            );
        }
        for task in &changes.stored {
            self.deliver(host, ToDevice::Task { task: task.clone() });
        }
    }
}

/// Why a task past the sandbox's [`MAX_TASKS`](enclos_protocol::task::MAX_TASKS)
/// still going is refused: the plugin sends it again with its next change.
fn full() -> String {
    format!(
        "the sandbox already has {} tasks still going; this one is not kept, and is taken when sent again once one has ended",
        enclos_protocol::task::MAX_TASKS
    )
}

/// `activity` as `person` may see it: all of it for the host's person, the
/// answering in their own conversations for anyone else.
fn seen_by(
    store: Option<&Store>,
    activity: &Activity,
    host: Option<&str>,
    person: &str,
) -> Activity {
    activity.for_person(host == Some(person), |c| {
        store
            .and_then(|s| s.owner(c.as_str()).ok().flatten())
            .as_deref()
            == Some(person)
    })
}

/// A reported task as the bridge keeps it: from the agent its connection
/// proves (`agent`, `<sandbox>/<agent>`), cleaned, its names made
/// `<sandbox>/<agent>`, and its conversation kept only when it is one of
/// the same sandbox owned by the host's person.
fn kept_form(
    store: &Store,
    agent: &str,
    host: Option<&str>,
    task: Task,
    now: i64,
) -> Result<Task, TaskRefusal> {
    let (sandbox, name) = agent.split_once('/').unwrap_or((agent, ""));
    if task.assignee != name {
        return Err(TaskRefusal::Bad(format!(
            "a task's assignee must be this plugin's agent, {name}"
        )));
    }
    let mut task = task
        .cleaned(now)
        .map_err(|e| TaskRefusal::Bad(e.to_string()))?;
    task.assignee = agent.to_owned();
    // Written `sandbox/agent`, it must still be a name a device takes: one
    // `/`, and the id rule's 128 bytes.
    task.asked_by = task
        .asked_by
        .filter(|a| !a.contains('/'))
        .map(|a| format!("{sandbox}/{a}"))
        .filter(|a| a.len() <= enclos_protocol::routine::MAX_ID_BYTES);
    if let Some(conversation) = &task.conversation {
        let id = conversation.as_str();
        let same_sandbox = store
            .conversation_info(id)
            .map_err(|e| TaskRefusal::Store(e.to_string()))?
            .is_some_and(|c| c.sandbox == sandbox);
        let owner = store
            .owner(id)
            .map_err(|e| TaskRefusal::Store(e.to_string()))?;
        if !same_sandbox || host.is_none() || owner.as_deref() != host {
            task.conversation = None;
        }
    }
    Ok(task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclos_protocol::task::{Doing, TaskState};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("app.db")).unwrap();
        store.claim_host("host@example.com").unwrap();
        (dir, store)
    }

    fn task(assignee: &str) -> Task {
        Task {
            id: "t1".into(),
            title: "Fix\u{202E} it\nnow".into(),
            assignee: assignee.into(),
            asked_by: Some("lead".into()),
            conversation: None,
            state: TaskState::Running,
            since: i64::MAX,
            summary: None,
        }
    }

    #[test]
    fn a_task_for_another_agent_is_refused() {
        let (_d, s) = store();
        assert!(matches!(
            kept_form(&s, "lab/engineer", Some("host@example.com"), task("lead"), 10),
            Err(TaskRefusal::Bad(why)) if why.contains("engineer")
        ));
        // Named the way the bridge names it, `sandbox/agent`, it is not the
        // plugin's own name for it either
        assert!(matches!(
            kept_form(&s, "lab/engineer", Some("host@example.com"), task("lab/engineer"), 10),
            Err(TaskRefusal::Bad(why)) if why.contains("engineer")
        ));
    }

    #[test]
    fn an_asked_by_that_would_not_be_a_name_is_dropped() {
        let (_d, s) = store();
        let asked = |by: &str| {
            let mut t = task("engineer");
            t.asked_by = Some(by.into());
            kept_form(&s, "lab/engineer", Some("host@example.com"), t, 10)
                .unwrap()
                .asked_by
        };
        assert_eq!(asked("other/lead"), None);
        assert_eq!(asked(&"l".repeat(128)), None);
        assert_eq!(asked(&"l".repeat(124)).map(|a| a.len()), Some(128));
    }

    #[test]
    fn activity_ends_only_with_the_connection_that_reported_it() {
        let dir = tempfile::tempdir().unwrap();
        let hub = super::super::tests::hub(dir.path(), &["main"]);
        let store = hub.store().unwrap();
        let busy = |task: &str| Activity {
            doing: vec![enclos_protocol::task::Doing::Task { task: task.into() }],
            since: 1,
        };
        let held = |hub: &Hub| {
            hub.activity
                .lock()
                .unwrap()
                .get("lab/main")
                .map(|(_, a)| a.clone())
        };
        hub.set_activity(Some(&store), "lab/main", 1, busy("old"));
        hub.set_activity(Some(&store), "lab/main", 2, busy("new"));
        // The old connection, closing late, leaves the new one's
        hub.end_activity(Some(&store), "lab/main", 1);
        assert_eq!(held(&hub), Some(busy("new")));
        // A late report from it is not taken either
        hub.set_activity(Some(&store), "lab/main", 1, busy("late"));
        assert_eq!(held(&hub), Some(busy("new")));
        // Its own connection closing, however it closed, ends it
        hub.end_activity(Some(&store), "lab/main", 2);
        assert_eq!(held(&hub), None);
        assert!(
            Store::read_activity(&dir.path().join("bridge.db"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_kept_task_is_cleaned_and_named_by_sandbox() {
        let (_d, s) = store();
        let kept = kept_form(
            &s,
            "lab/engineer",
            Some("host@example.com"),
            task("engineer"),
            10,
        )
        .unwrap();
        assert_eq!(kept.title, "Fix it now");
        assert_eq!(kept.assignee, "lab/engineer");
        assert_eq!(kept.asked_by.as_deref(), Some("lab/lead"));
        assert_eq!(kept.since, 10);
    }

    #[test]
    fn a_conversation_is_kept_only_in_the_same_sandbox_and_the_hosts() {
        let (_d, s) = store();
        s.conversation("c-lab", "lab", "lead", "host@example.com")
            .unwrap();
        s.conversation("c-other", "other", "lead", "host@example.com")
            .unwrap();
        s.conversation("c-guest", "lab", "lead", "guest@example.com")
            .unwrap();
        let with = |id: &str| {
            let mut t = task("engineer");
            t.conversation = Some(enclos_protocol::ConversationId::new(id).unwrap());
            kept_form(&s, "lab/engineer", Some("host@example.com"), t, 10)
                .unwrap()
                .conversation
                .map(|c| c.as_str().to_owned())
        };
        assert_eq!(with("c-lab").as_deref(), Some("c-lab"));
        assert_eq!(with("c-other"), None);
        assert_eq!(with("c-guest"), None);
        assert_eq!(with("c-unknown"), None);
    }

    #[test]
    fn another_person_sees_only_answering_in_their_own_conversations() {
        let (_d, s) = store();
        s.conversation("mine", "lab", "eng", "guest@example.com")
            .unwrap();
        let activity = Activity {
            doing: vec![
                Doing::Answering {
                    conversation: enclos_protocol::ConversationId::new("mine").unwrap(),
                },
                Doing::Task { task: "t1".into() },
            ],
            since: 3,
        };
        let guest = seen_by(
            Some(&s),
            &activity,
            Some("host@example.com"),
            "guest@example.com",
        );
        assert_eq!(guest.doing.len(), 1);
        let host = seen_by(
            Some(&s),
            &activity,
            Some("host@example.com"),
            "host@example.com",
        );
        assert_eq!(host, activity);
    }
}
