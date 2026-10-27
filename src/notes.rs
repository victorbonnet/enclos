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
    match SINK.get() {
        Some(sink) => sink(what),
        None => {
            let _ = writeln!(std::io::stderr(), "enclos: {what}");
        }
    }
}
