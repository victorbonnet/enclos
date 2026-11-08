//! Group conversations' rules, without I/O (ADR 0045, proposed;
//! `docs/protocol.md`, Groups): who a message addresses, whether a reply
//! passes, and what a member is given for its turn. The semantics are
//! Hermes's hosted rooms': handles, `@all`, `(pass)`, rounds and bounds.

/// The most members a group has, and the fewest.
pub const MAX_MEMBERS: usize = 6;
pub const MIN_MEMBERS: usize = 2;
/// Rounds of one discussion, the person's message's first included.
pub const MAX_ROUNDS: u32 = 3;
/// Agent messages in one discussion.
pub const MAX_REPLIES: u32 = 10;
/// The group's messages a member is given for a turn, the newest kept.
pub const MAX_UNSEEN: usize = 24;
/// How long a member's turn may run before it fails.
pub const TURN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What a reply that passes says.
pub const PASS: &str = "(pass)";

/// The handles `text` mentions among `handles` (members' names in their
/// sandbox), each once, in the group's order; `@all` and `@everyone` mention
/// every member. Matched whatever the case; a handle ends at the first
/// character that cannot be in one, and a trailing `.`, `:` or `-` is
/// punctuation, not the handle's.
pub fn mentions(text: &str, handles: &[String]) -> Vec<String> {
    let mut said: Vec<String> = Vec::new();
    for (i, c) in text.char_indices() {
        if c != '@' {
            continue;
        }
        // Not inside a word or an address: `a@b` is no mention.
        if text[..i]
            .chars()
            .next_back()
            .is_some_and(|p| p.is_alphanumeric())
        {
            continue;
        }
        let rest = &text[i + 1..];
        let end = rest
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-')))
            .unwrap_or(rest.len());
        let word = rest[..end].trim_end_matches(['.', ':', '-']).to_lowercase();
        if !word.is_empty() {
            said.push(word);
        }
    }
    if said.iter().any(|w| w == "all" || w == "everyone") {
        return handles.to_vec();
    }
    handles
        .iter()
        .filter(|h| said.iter().any(|w| w == &h.to_lowercase()))
        .cloned()
        .collect()
}

/// Who a person's message addresses: those it mentions, else every member.
pub fn addressed(text: &str, handles: &[String]) -> (Vec<String>, bool) {
    let named = mentions(text, handles);
    if named.is_empty() {
        (handles.to_vec(), false)
    } else {
        (named, true)
    }
}

/// Whether a member's reply passes: empty, or `(pass)`, with or without its
/// parentheses and a final dot, whatever the case.
pub fn is_pass(text: &str) -> bool {
    let t = text.trim().trim_end_matches('.').trim();
    let t = t.strip_prefix('(').unwrap_or(t);
    let t = t.strip_suffix(')').unwrap_or(t);
    t.is_empty() || t.trim().eq_ignore_ascii_case("pass")
}

/// A message of the group as a member is given it.
pub struct Said<'a> {
    /// `None` for the person.
    pub member: Option<&'a str>,
    pub person: &'a str,
    pub text: &'a str,
}

/// What a member is sent for its turn: the group, who it is among whom,
/// the group's messages it has not seen (the newest [`MAX_UNSEEN`], oldest
/// first, with who said each), and the rules. A member the person
/// addressed by name ([`addressed`]) must answer or say what blocks it.
pub fn prompt(title: &str, me: &str, others: &[String], unseen: &[Said], direct: bool) -> String {
    let with = if others.is_empty() {
        "no other members".to_owned()
    } else {
        others
            .iter()
            .map(|o| format!("@{o}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = format!(
        "[Group: \"{title}\"] You are @{me}, one participant with {with} and the user.\n\n"
    );
    out.push_str("New messages in this group since your last turn (oldest first):\n");
    let skipped = unseen.len().saturating_sub(MAX_UNSEEN);
    if skipped > 0 {
        out.push_str("  [Earlier messages omitted.]\n");
    }
    for s in &unseen[skipped..] {
        let who = match s.member {
            Some(m) => format!("@{m}"),
            None => format!("User ({})", s.person),
        };
        // One line each: a message's own lines are indented under it.
        let text = s.text.trim().replace('\n', "\n    ");
        out.push_str(&format!("  {who}: {text}\n"));
    }
    out.push_str("\nRules for this group:\n");
    if direct {
        out.push_str("- The user directly addressed you. Reply with your answer, result, or concrete blocker.\n");
        out.push_str(&format!("- Do not return \"{PASS}\". If you cannot proceed, explain why and what you need from the user.\n"));
    } else {
        out.push_str("- Reply with one conversational message only when you have something new worth adding.\n");
        out.push_str(&format!(
            "- If you have nothing new to add, reply with exactly \"{PASS}\".\n"
        ));
    }
    out.push_str("- Mention a teammate by handle to pull them into the next round; do not repeat points already made.\n");
    out.push_str(
        "- Never reveal content from private conversations. Your reply is published verbatim.\n",
    );
    out
}

/// A turn's id, the same for the same group, person's message, round and
/// member: a retry finds the turn instead of running it again.
pub fn turn_id(group: &str, source: i64, round: u32, member: &str) -> String {
    format!("turn.{group}.{source}.{round}.{member}")
}

/// The turn a member is running: what it was sent, and what it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    pub member: String,
    pub turn: String,
    /// The plugin message the turn was sent as; the member's reply answers it.
    pub sent: String,
    /// The group's newest message when the turn was sent.
    pub seen: i64,
    /// Whether the person addressed the member by name: it may not pass.
    pub direct: bool,
    pub started: std::time::Instant,
}

/// How a member's turn ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// Its reply is published, and asks the members it mentions for a turn.
    Replied,
    Passed,
    /// It passed though the person addressed it by name.
    Failed(String),
}

/// One group's discussion: the person's message that started it, the
/// rounds, and who is queued, running or done. The bridge keeps one per
/// group while it runs; its turns are also stored.
#[derive(Debug, Clone)]
pub struct Discussion {
    /// The person's message (its `seq`) that started it.
    pub source: i64,
    pub round: u32,
    /// This round's members still to run, each with whether it was addressed by name.
    pub queue: std::collections::VecDeque<(String, bool)>,
    /// Members mentioned by this round's replies, for the next.
    pub next: Vec<String>,
    pub replies: u32,
    /// Whether this round brought a message.
    pub spoke: bool,
    pub running: Option<Running>,
    /// A newer message of the person's, waiting behind the running turn.
    pub pending: Option<(i64, String)>,
    /// Each member's turn in this discussion: `queued`, `working`,
    /// `replied`, `passed`, `failed`, `cancelled`.
    pub turns: std::collections::HashMap<String, String>,
    /// `working`, `settled`, `bounded`, `stopped` or `failed`.
    pub state: String,
    pub reason: Option<String>,
}

impl Discussion {
    /// A discussion started by the person's message `source` saying `text`,
    /// among `handles`: its first round queued.
    pub fn new(source: i64, text: &str, handles: &[String]) -> Discussion {
        let mut d = Discussion {
            source,
            round: 0,
            queue: Default::default(),
            next: Vec::new(),
            replies: 0,
            spoke: false,
            running: None,
            pending: None,
            turns: Default::default(),
            state: "working".to_owned(),
            reason: None,
        };
        let (first, by_name) = addressed(text, handles);
        for member in first {
            d.turns.insert(member.clone(), "queued".to_owned());
            d.queue.push_back((member, by_name));
        }
        d
    }

    /// The person said something new while a turn runs: it waits, and the
    /// members queued for this discussion are cancelled.
    pub fn wait_for(&mut self, source: i64, text: &str) {
        for (member, _) in self.queue.drain(..) {
            self.turns.insert(member, "cancelled".to_owned());
        }
        self.next.clear();
        self.pending = Some((source, text.to_owned()));
    }

    /// The next member to run, and whether it was addressed by name; or
    /// none, the discussion over (settled or bounded) or a turn running.
    /// `fresh` says whether a member has messages it has not seen: one
    /// with none is skipped.
    pub fn next_turn(
        &mut self,
        handles: &[String],
        fresh: impl Fn(&str) -> bool,
    ) -> Option<(String, bool)> {
        if self.running.is_some() || self.state != "working" {
            return None;
        }
        loop {
            if let Some((member, direct)) = self.queue.pop_front() {
                if fresh(&member) {
                    return Some((member, direct));
                }
                self.turns.insert(member, "passed".to_owned());
                continue;
            }
            // The round is over: settle, bound, or go on with those mentioned.
            if !self.spoke || self.next.is_empty() {
                self.end("settled", None);
                return None;
            }
            if self.replies >= MAX_REPLIES {
                self.end("bounded", Some("max_replies"));
                return None;
            }
            if self.round + 1 >= MAX_ROUNDS {
                self.end("bounded", Some("max_rounds"));
                return None;
            }
            self.round += 1;
            self.spoke = false;
            let mentioned = std::mem::take(&mut self.next);
            for member in handles.iter().filter(|h| mentioned.contains(h)) {
                self.turns.insert(member.clone(), "queued".to_owned());
                self.queue.push_back((member.clone(), false));
            }
        }
    }

    /// A member's turn started, sent as plugin message `sent`.
    pub fn started(&mut self, member: &str, turn: String, sent: String, seen: i64, direct: bool) {
        self.turns.insert(member.to_owned(), "working".to_owned());
        self.running = Some(Running {
            member: member.to_owned(),
            turn,
            sent,
            seen,
            direct,
            started: std::time::Instant::now(),
        });
    }

    /// The running member replied `text`: how its turn ended. A reply
    /// asks the members it mentions, other than its speaker, for a turn
    /// in the next round.
    pub fn replied(&mut self, text: &str, handles: &[String]) -> Ended {
        let Some(run) = self.running.take() else {
            return Ended::Passed;
        };
        if is_pass(text) {
            if run.direct {
                let why = format!(
                    "@{} was directly addressed but returned no visible reply.",
                    run.member
                );
                self.turns.insert(run.member, "failed".to_owned());
                return Ended::Failed(why);
            }
            self.turns.insert(run.member, "passed".to_owned());
            return Ended::Passed;
        }
        self.replies += 1;
        self.spoke = true;
        for m in mentions(text, handles) {
            if m != run.member && !self.next.contains(&m) {
                self.next.push(m);
            }
        }
        self.turns.insert(run.member, "replied".to_owned());
        Ended::Replied
    }

    /// The running turn failed (no reply in time, the bridge restarted).
    pub fn failed(&mut self) {
        if let Some(run) = self.running.take() {
            self.turns.insert(run.member, "failed".to_owned());
        }
    }

    /// The person stopped it: what is queued is cancelled, and the running
    /// turn, which is returned.
    pub fn stop(&mut self) -> Option<Running> {
        for (member, _) in self.queue.drain(..) {
            self.turns.insert(member, "cancelled".to_owned());
        }
        self.next.clear();
        self.pending = None;
        let run = self.running.take();
        if let Some(r) = &run {
            self.turns.insert(r.member.clone(), "cancelled".to_owned());
        }
        self.end("stopped", None);
        run
    }

    fn end(&mut self, state: &str, reason: Option<&str>) {
        self.state = state.to_owned();
        self.reason = reason.map(str::to_owned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `d` to its end, each member replying what `say` returns for it
    /// in its round; the members in the order they ran.
    fn run(d: &mut Discussion, say: impl Fn(&str, u32) -> String) -> Vec<String> {
        let mut ran = Vec::new();
        while let Some((m, direct)) = d.next_turn(&handles(), |_| true) {
            d.started(&m, "t".into(), "s".into(), 0, direct);
            let text = say(&m, d.round);
            d.replied(&text, &handles());
            ran.push(m);
        }
        ran
    }

    #[test]
    fn a_message_naming_no_one_runs_every_member_then_settles() {
        let mut d = Discussion::new(1, "hello", &handles());
        assert_eq!(run(&mut d, |_, _| "hi".into()), handles());
        assert_eq!((d.state.as_str(), d.round), ("settled", 0));
    }

    #[test]
    fn mentions_in_replies_bring_members_into_the_next_round_until_bounded() {
        let mut d = Discussion::new(1, "@main start", &handles());
        // main asks coder, coder asks main, and so on.
        let ran = run(&mut d, |m, _| {
            if m == "main" {
                "@coder over to you".into()
            } else {
                "@main back".into()
            }
        });
        assert_eq!(ran, ["main", "coder", "main"]);
        assert_eq!(
            (d.state.as_str(), d.reason.as_deref()),
            ("bounded", Some("max_rounds"))
        );
    }

    #[test]
    fn a_round_where_everyone_passes_settles() {
        let mut d = Discussion::new(1, "ideas?", &handles());
        assert_eq!(run(&mut d, |_, _| "(pass)".into()), handles());
        assert_eq!(d.state, "settled");
        assert_eq!(d.turns["coder"], "passed");
    }

    #[test]
    fn all_expects_an_answer_from_every_member() {
        let mut d = Discussion::new(1, "@all ideas?", &handles());
        run(&mut d, |_, _| "(pass)".into());
        assert!(d.turns.values().all(|t| t == "failed"));
    }

    #[test]
    fn a_member_addressed_by_name_may_not_pass() {
        let mut d = Discussion::new(1, "@coder fix it", &handles());
        let (m, direct) = d.next_turn(&handles(), |_| true).unwrap();
        assert!(direct);
        d.started(&m, "t".into(), "s".into(), 0, direct);
        assert!(matches!(d.replied("(pass)", &handles()), Ended::Failed(_)));
        assert_eq!(d.turns["coder"], "failed");
    }

    #[test]
    fn stop_cancels_what_is_queued_and_the_running_turn() {
        let mut d = Discussion::new(1, "hello", &handles());
        let (m, _) = d.next_turn(&handles(), |_| true).unwrap();
        d.started(&m, "t".into(), "sent-1".into(), 0, false);
        assert_eq!(d.stop().map(|r| r.sent), Some("sent-1".into()));
        assert_eq!(d.state, "stopped");
        assert!(d.turns.values().all(|t| t == "cancelled"));
        assert!(d.next_turn(&handles(), |_| true).is_none());
    }

    #[test]
    fn a_new_message_cancels_the_queue_and_waits_for_the_running_turn() {
        let mut d = Discussion::new(1, "hello", &handles());
        let (m, _) = d.next_turn(&handles(), |_| true).unwrap();
        d.started(&m, "t".into(), "s".into(), 0, false);
        d.wait_for(9, "@writer instead");
        assert_eq!(d.turns["coder"], "cancelled");
        assert_eq!(d.pending, Some((9, "@writer instead".into())));
        assert!(
            d.next_turn(&handles(), |_| true).is_none(),
            "the turn still runs"
        );
    }

    fn handles() -> Vec<String> {
        vec!["main".into(), "coder".into(), "writer".into()]
    }

    #[test]
    fn mentions_are_handles_whatever_the_case_in_the_groups_order() {
        assert_eq!(
            mentions("@Writer and @main, please.", &handles()),
            ["main", "writer"]
        );
        assert_eq!(mentions("ask @coder.", &handles()), ["coder"]);
        assert_eq!(mentions("@coder: look", &handles()), ["coder"]);
        assert!(mentions("mail me at a@main.com or @nobody", &handles()).is_empty());
    }

    #[test]
    fn all_and_everyone_mention_every_member() {
        assert_eq!(mentions("@all thoughts?", &handles()), handles());
        assert_eq!(mentions("@Everyone", &handles()), handles());
    }

    #[test]
    fn a_message_naming_no_one_addresses_everyone_and_not_by_name() {
        assert_eq!(
            addressed("what do you think?", &handles()),
            (handles(), false)
        );
        assert_eq!(
            addressed("@coder fix it", &handles()),
            (vec!["coder".to_owned()], true)
        );
    }

    #[test]
    fn a_pass_is_empty_or_pass_with_or_without_its_marks() {
        for p in ["(pass)", "pass", "(Pass).", "  ( pass )  ", ""] {
            assert!(is_pass(p), "{p:?}");
        }
        for p in ["I pass on that, but here is why", "passing thought"] {
            assert!(!is_pass(p), "{p:?}");
        }
    }

    #[test]
    fn the_prompt_names_who_is_who_and_keeps_the_newest_unseen() {
        let many: Vec<String> = (0..30).map(|i| format!("m{i}")).collect();
        let unseen: Vec<Said> = many
            .iter()
            .map(|t| Said {
                member: Some("coder"),
                person: "",
                text: t,
            })
            .chain([Said {
                member: None,
                person: "victor",
                text: "line one\nline two",
            }])
            .collect();
        let p = prompt("Launch", "main", &["coder".into()], &unseen, false);
        assert!(p.starts_with(
            "[Group: \"Launch\"] You are @main, one participant with @coder and the user."
        ));
        assert!(p.contains("[Earlier messages omitted.]"));
        assert!(
            !p.contains("@coder: m6\n")
                && p.contains("@coder: m7\n")
                && p.contains("@coder: m29\n")
        );
        assert!(p.contains("User (victor): line one\n    line two"));
        assert!(p.contains("reply with exactly \"(pass)\""));
    }

    #[test]
    fn a_member_addressed_by_name_is_told_not_to_pass() {
        let p = prompt("G", "main", &[], &[], true);
        assert!(p.contains("no other members"));
        assert!(p.contains("The user directly addressed you"));
        assert!(!p.contains("reply with exactly"));
    }
}
