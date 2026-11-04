//! enclos's notes from inside the library, such as a test item left in the
//! Keychain: said on stderr as the client says its own, so that a client
//! printing JSON gets them as JSON lines, not as text among them.

use std::io::Write;
use std::sync::OnceLock;

static SINK: OnceLock<fn(&str)> = OnceLock::new();

/// Where notes go from now on: set once, by the client, before anything is
/// said. Until then, and without one, a note is an `enclos: …` line.
pub fn send_to(sink: fn(&str)) {
    let _ = SINK.set(sink);
}

/// Says `what`, a sentence with no `enclos:` of its own. A stderr closed
/// already never makes it fail.
pub fn say(what: &str) {
    #[cfg(test)]
    if HEARD
        .with(|h| {
            h.borrow_mut()
                .as_mut()
                .map(|said| said.push(what.to_owned()))
        })
        .is_some()
    {
        return;
    }
    match SINK.get() {
        Some(sink) => sink(what),
        None => {
            let _ = writeln!(std::io::stderr(), "enclos: {what}");
        }
    }
}

#[cfg(test)]
thread_local! {
    /// What this thread said, while [`heard`] listens.
    static HEARD: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `work` and returns, with its result, every note this thread said
/// meanwhile, which then goes nowhere else.
#[cfg(test)]
pub fn heard<T>(work: impl FnOnce() -> T) -> (T, Vec<String>) {
    HEARD.with(|h| *h.borrow_mut() = Some(Vec::new()));
    let done = work();
    let said = HEARD.with(|h| h.borrow_mut().take()).unwrap_or_default();
    (done, said)
}
