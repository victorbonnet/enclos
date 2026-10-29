//! `enclos secret`: set, list or remove a sandbox's secrets (design §12,
//! ADR 0022). A value is read from the input, never from the command line,
//! which other processes can list.

use std::io::{IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;

use clap::{Args, Subcommand};

use enclos::engine::{Engine, SecretSet, SecretView};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;
use enclos::model::secret::{SecretRef, SecretValue};

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    verb: SecretVerb,
}

#[derive(Subcommand)]
enum SecretVerb {
    /// Store a secret of a sandbox in the Keychain, reading its value from
    /// the input: one line typed without echo at a terminal, or all of what
    /// is piped in, its final line ending left out.
    Set {
        /// `<sandbox>/<name>`, such as `home/telegram`.
        secret: SecretRef,
    },
    /// List a sandbox's secrets and what its policy gives each as; never
    /// their values.
    List { sandbox: SandboxName },
    /// Remove a secret of a sandbox from the Keychain.
    Rm { secret: SecretRef },
}

pub fn run(engine: &Engine, by: &Actor, confirm: Confirm, args: SecretArgs) -> Result<u8> {
    match args.verb {
        SecretVerb::Set { secret } => {
            engine.require_sandbox(&secret.sandbox)?;
            let value = match confirm {
                // A dry run reads nothing: nothing would be stored.
                Confirm::DryRun => None,
                _ => Some(read_value(&secret)?),
            };
            match engine.secret_set(by, &secret, value.as_ref(), confirm)? {
                Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
                Planned::Done(set) => print_set(&secret, &set),
            }
        }
        SecretVerb::List { sandbox } => print_list(&sandbox, &engine.secret_list(&sandbox)?),
        SecretVerb::Rm { secret } => match engine.secret_rm(by, &secret, confirm)? {
            Planned::DryRun(plan) => plan.changes.iter().for_each(|c| println!("Would {c}.")),
            Planned::Done(()) => println!("Removed secret {secret} from the Keychain."),
        },
    }
    Ok(exit::OK)
}

/// The most read from a pipe: far more than the Keychain takes.
const MAX_INPUT: usize = 1 << 20;

/// The most typed at a terminal: a longer value is piped in.
const MAX_TYPED: usize = 4096;

/// The value from the input. At a terminal it asks for one line, with echo
/// off, so the value never shows on screen; piped in, it is all the input,
/// so a value of several lines (a PEM file) comes whole.
fn read_value(secret: &SecretRef) -> Result<SecretValue> {
    let stdin = std::io::stdin();
    let io = |e: std::io::Error| Error::Session {
        what: format!("cannot read the value of secret {secret}: {e}"),
    };
    let refused = |why: &str| Error::Session {
        what: format!("secret {secret} was not set: {why}"),
    };
    let bytes = if stdin.is_terminal() {
        eprint!("Value of secret {secret} (not shown): ");
        let _ = std::io::stderr().flush();
        let quiet = Quiet::new(&stdin).map_err(io)?;
        let typed = typed(&mut std::iter::from_fn(|| {
            let mut key = [0u8; 1];
            match rustix::io::read(&stdin, &mut key) {
                Ok(0) => None,
                Ok(_) => Some(Ok(key[0])),
                Err(e) => Some(Err(std::io::Error::from(e))),
            }
        }));
        // Everything that came after the line, such as more pasted lines or
        // the rest of a value too long, is read and dropped before echo
        // comes back, so the shell never reads it: up to the end of a paste
        // the line ended in, then until the input stays quiet.
        let paste_open = matches!(typed, Ok((_, true)));
        let after = quiet.drain(paste_open);
        quiet.restore();
        eprintln!();
        let (typed, _) = typed.map_err(io)?;
        let after = after.map_err(|e| {
            refused(&format!(
                "what came after the line could not all be dropped, and may reach the shell: {e}"
            ))
        })?;
        match typed {
            Typed::Cancelled => {
                return Err(Error::Session {
                    what: format!("cancelled: secret {secret} was not set"),
                });
            }
            Typed::Ended => {
                return Err(refused(
                    "nothing was typed, or the input ended before Return",
                ));
            }
            Typed::TooLong => {
                return Err(refused(&format!(
                    "a value typed at a terminal is at most {MAX_TYPED} bytes"
                )));
            }
            Typed::Control(key) => {
                return Err(refused(&format!(
                    "{} is no part of a value, and nothing was stored; type it again, or pipe it in",
                    key_name(key)
                )));
            }
            Typed::Line(_) if after => {
                return Err(refused(
                    "more came after the line, and was dropped: at a terminal a value is one line; pipe in one of several lines",
                ));
            }
            Typed::Line(line) => line,
        }
    } else {
        let mut bytes = Vec::new();
        stdin
            .lock()
            .take(MAX_INPUT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() > MAX_INPUT {
            return Err(refused("the input is more than 1 MiB"));
        }
        bytes
    };
    let text = String::from_utf8(bytes).map_err(|_| refused("the value is not UTF-8 text"))?;
    let value = text
        .strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(&text);
    SecretValue::new(value.to_owned()).map_err(|e| refused(&e.to_string()))
}

/// What was typed at the prompt.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    Line(Vec<u8>),
    /// Ctrl-C, Ctrl-Z or Ctrl-\.
    Cancelled,
    /// The input ended before Return, or Ctrl-D on an empty line.
    Ended,
    /// More than [`MAX_TYPED`] bytes.
    TooLong,
    /// A control key that edits nothing here, such as Escape or an arrow.
    Control(u8),
}

/// A line from `keys`, as a terminal in line mode would make it, but with
/// no limit of its own: Return ends it, and so does Ctrl-D after some
/// text; Backspace erases a character, Ctrl-W a word and Ctrl-U the line;
/// the keys that would signal cancel it at once, and any other control key
/// is refused rather than taken into the value unseen. The marks a terminal
/// puts around a paste (bracketed paste) are taken out; the second value
/// says whether the line ended inside a paste, of which more then follows.
fn typed(keys: &mut impl Iterator<Item = std::io::Result<u8>>) -> std::io::Result<(Typed, bool)> {
    let mut line = Vec::new();
    let mut pasting = false;
    let typed = loop {
        let Some(key) = keys.next() else {
            break Typed::Ended;
        };
        match key? {
            b'\r' | b'\n' => break Typed::Line(line),
            0x04 if line.is_empty() => break Typed::Ended,
            0x04 => break Typed::Line(line),
            0x03 | 0x1a | 0x1c => break Typed::Cancelled,
            0x1b => match paste_mark(keys)? {
                Mark::Starts => pasting = true,
                Mark::Ends => pasting = false,
                Mark::Cancelled => break Typed::Cancelled,
                Mark::Not { then } => {
                    // A mark right after the Escape still says where a
                    // paste stands, so its end is not waited for in vain.
                    if let Some(open) = then {
                        pasting = open;
                    }
                    break Typed::Control(0x1b);
                }
            },
            // A character's last byte, and any continuation bytes before it.
            0x7f | 0x08 => {
                while let Some(byte) = line.pop() {
                    if byte & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            0x17 => {
                while line.last().is_some_and(u8::is_ascii_whitespace) {
                    line.pop();
                }
                while line.last().is_some_and(|b| !b.is_ascii_whitespace()) {
                    line.pop();
                }
            }
            0x15 => line.clear(),
            key @ (0x00..=0x08 | 0x0a..=0x1f) => break Typed::Control(key),
            _ if line.len() == MAX_TYPED => break Typed::TooLong,
            byte => line.push(byte),
        }
    };
    Ok((typed, pasting))
}

/// What a terminal in bracketed paste mode sends before a paste, after
/// Escape, and after it.
const PASTE_STARTS: &[u8; 5] = b"[200~";
const PASTE_ENDS: &[u8; 5] = b"[201~";

/// What followed an Escape.
enum Mark {
    Starts,
    Ends,
    /// A key that would signal: the read is cancelled at once.
    Cancelled,
    /// Anything else: an Escape or an arrow key, refused; `then` is whether
    /// a paste is open after a mark that followed at once, if one did.
    Not {
        then: Option<bool>,
    },
}

/// Reads what follows an Escape as far as it can be a paste's mark, and no
/// further: the first byte that cannot continue one ends it, so a lone
/// Escape or an arrow key takes no more keys than its own. Another Escape
/// starts a mark again: it may be a paste's end.
fn paste_mark(keys: &mut impl Iterator<Item = std::io::Result<u8>>) -> std::io::Result<Mark> {
    let mut read = Vec::new();
    let mut lone = false;
    while read.len() < PASTE_STARTS.len() {
        let Some(byte) = keys.next().transpose()? else {
            return Ok(Mark::Not { then: None });
        };
        if matches!(byte, 0x03 | 0x1a | 0x1c) {
            return Ok(Mark::Cancelled);
        }
        if byte == 0x1b {
            read.clear();
            lone = true;
            continue;
        }
        read.push(byte);
        if !PASTE_STARTS.starts_with(&read) && !PASTE_ENDS.starts_with(&read) {
            return Ok(Mark::Not { then: None });
        }
    }
    let open = read.as_slice() == PASTE_STARTS;
    Ok(match (lone, open) {
        (true, open) => Mark::Not { then: Some(open) },
        (false, true) => Mark::Starts,
        (false, false) => Mark::Ends,
    })
}

/// Whether `drained`, what came after the line, holds anything but the
/// marks around a paste and line endings.
fn holds_more(drained: &[u8]) -> bool {
    let mut rest = drained;
    while !rest.is_empty() {
        if let Some(after) = rest
            .strip_prefix(b"\x1b")
            .and_then(|r| r.strip_prefix(PASTE_STARTS).or(r.strip_prefix(PASTE_ENDS)))
        {
            rest = after;
            continue;
        }
        if !matches!(rest[0], b'\r' | b'\n') {
            return true;
        }
        rest = &rest[1..];
    }
    false
}

/// How a control key is named to the user.
fn key_name(key: u8) -> String {
    match key {
        0x1b => "Escape, or an arrow key,".to_owned(),
        key => format!("Ctrl-{}", char::from(key + 0x40)),
    }
}

/// The terminal with echo, line mode and its signal keys off while it
/// lives: [`typed`] makes the line, so the terminal's own line limit does
/// not apply, and Ctrl-C ends the read at once rather than enclos, which
/// would leave echo off.
struct Quiet<'a> {
    stdin: &'a std::io::Stdin,
    before: Option<rustix::termios::Termios>,
    /// The terminal, to turn bracketed paste on and off; none when it
    /// cannot be opened, and then the end of a paste is not known.
    tty: Option<std::fs::File>,
}

impl<'a> Quiet<'a> {
    fn new(stdin: &'a std::io::Stdin) -> std::io::Result<Self> {
        use rustix::termios::{
            LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr,
        };
        let before = tcgetattr(stdin)?;
        let mut quiet = before.clone();
        quiet
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
        // Each key as it comes.
        quiet.special_codes[SpecialCodeIndex::VMIN] = 1;
        quiet.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(stdin, OptionalActions::Now, &quiet)?;
        // Bracketed paste, so a paste's end is known whatever pauses its
        // bytes come with (ssh on a slow link, a slow paste).
        // On the terminal the value is read from, which need not be the
        // controlling one.
        let tty = rustix::termios::ttyname(stdin, Vec::new())
            .ok()
            .and_then(|path| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(std::ffi::OsStr::from_bytes(path.as_bytes()))
                    .ok()
            })
            .filter(|mut tty| tty.write_all(b"\x1b[?2004h").is_ok());
        Ok(Quiet {
            stdin,
            before: Some(before),
            tty,
        })
    }

    /// Reads and drops what is waiting: up to the end of the paste when
    /// `paste_open`, then until nothing more comes for half a second, and
    /// flushes the rest. A paste longer than the terminal's queue keeps
    /// refilling it, so one flush is not enough. Returns whether anything
    /// but the end of a paste came.
    fn drain(&self, paste_open: bool) -> std::io::Result<bool> {
        use rustix::termios::{OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        let drained = tcgetattr(self.stdin)
            .and_then(|mut waiting| {
                waiting.special_codes[SpecialCodeIndex::VMIN] = 0;
                waiting.special_codes[SpecialCodeIndex::VTIME] = 5;
                tcsetattr(self.stdin, OptionalActions::Now, &waiting)
            })
            .map_err(std::io::Error::from)
            .and_then(|()| self.drained(paste_open));
        // Flushed whatever happened, so as little as can be reaches the
        // shell when it went wrong.
        let flushed = rustix::termios::tcflush(self.stdin, rustix::termios::QueueSelector::IFlush);
        let drained = drained?;
        flushed?;
        Ok(holds_more(&drained))
    }

    /// What `drain` reads, at most [`MAX_INPUT`] bytes, and for a paste
    /// still open, at most half a minute.
    fn drained(&self, mut paste_open: bool) -> std::io::Result<Vec<u8>> {
        let started = std::time::Instant::now();
        let mut buf = [0u8; 4096];
        let mut drained = Vec::new();
        loop {
            let read = rustix::io::read(self.stdin, &mut buf[..])?;
            if read == 0 && !paste_open {
                return Ok(drained);
            }
            drained.extend_from_slice(&buf[..read]);
            // Where the last mark is says whether a paste is still open.
            let tail = &drained[drained.len().saturating_sub(read + 5)..];
            let last = |mark: &[u8]| {
                tail.windows(6)
                    .rposition(|w| w[0] == 0x1b && &w[1..] == mark)
            };
            match (last(PASTE_STARTS), last(PASTE_ENDS)) {
                (Some(start), Some(end)) => paste_open = start > end,
                (Some(_), None) => paste_open = true,
                (None, Some(_)) => paste_open = false,
                (None, None) => {}
            }
            if drained.len() > MAX_INPUT {
                return Err(std::io::Error::other("the input does not stop"));
            }
            if paste_open && started.elapsed() > std::time::Duration::from_secs(30) {
                return Err(std::io::Error::other("a paste did not end"));
            }
        }
    }

    /// Puts the terminal back as it was, saying so when it cannot.
    fn restore(mut self) {
        self.put_back();
    }

    fn put_back(&mut self) {
        if let Some(mut tty) = self.tty.take()
            && let Err(e) = tty.write_all(b"\x1b[?2004l")
        {
            eprintln!(
                "\nwarning: cannot turn the terminal's bracketed paste back off ({e}); run `printf '\\e[?2004l'`"
            );
        }
        if let Some(before) = self.before.take()
            && let Err(e) = rustix::termios::tcsetattr(
                self.stdin,
                rustix::termios::OptionalActions::Now,
                &before,
            )
        {
            eprintln!("\nwarning: cannot turn the terminal's echo back on ({e}); run `stty sane`");
        }
    }
}

impl Drop for Quiet<'_> {
    fn drop(&mut self) {
        self.put_back();
    }
}

fn print_set(secret: &SecretRef, set: &SecretSet) {
    match set.new {
        true => println!("Stored secret {secret} in the Keychain."),
        false => println!("Replaced the value of secret {secret} in the Keychain."),
    }
    let sandbox = &secret.sandbox;
    let shown = |variables: &[String]| {
        variables
            .iter()
            .map(|v| format!("${v}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match set.granted_as.as_slice() {
        [] if !set.pending_as.is_empty() => println!(
            "The pending policy gives it as {}, from `enclos policy apply {sandbox}`.",
            shown(&set.pending_as)
        ),
        [] => println!(
            "No session gets it until the policy grants it: `enclos policy edit {sandbox}`, under [secrets], as `env = {{ NAME = \"{}\" }}`.",
            secret.in_policy()
        ),
        variables => {
            println!(
                "Sessions started from now on get it as {}.",
                shown(variables)
            );
            if set.running > 0 {
                println!(
                    "{} running session(s) keep the value they started with; `enclos sandbox restart {sandbox}` gives them this one.",
                    set.running
                );
            }
        }
    }
}

fn print_list(sandbox: &SandboxName, secrets: &[SecretView]) {
    if secrets.is_empty() {
        println!(
            "Sandbox {sandbox} has no secrets. Add one with `enclos secret set {sandbox}/<name>`."
        );
        return;
    }
    println!("Secrets of sandbox {sandbox} (values are in the Keychain, never shown):");
    for s in secrets {
        let shown = |vars: &[String]| match vars {
            [] => "not granted".to_owned(),
            vars => vars
                .iter()
                .map(|v| format!("${v}"))
                .collect::<Vec<_>>()
                .join(", "),
        };
        let pending = match &s.pending_as {
            Some(vars) if *vars != s.granted_as => format!("; pending: {}", shown(vars)),
            _ => String::new(),
        };
        println!(
            "  {:<24} {}{pending}  (set {})",
            s.record.secret.name.as_str(),
            shown(&s.granted_as),
            s.record.updated_at.strftime("%Y-%m-%d %H:%M UTC"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(bytes: &[u8]) -> std::io::Result<Typed> {
        typed(&mut bytes.iter().map(|b| Ok(*b))).map(|(typed, _)| typed)
    }

    #[test]
    fn the_marks_around_a_paste_are_taken_out_and_say_whether_it_goes_on() {
        let pasted = |bytes: &[u8]| typed(&mut bytes.iter().map(|b| Ok(*b))).unwrap();
        assert_eq!(
            pasted(b"\x1b[200~tok\x1b[201~\r"),
            (Typed::Line(b"tok".to_vec()), false)
        );
        assert_eq!(
            pasted(b"\x1b[200~tok\rsecond"),
            (Typed::Line(b"tok".to_vec()), true)
        );
        assert!(!holds_more(b"\x1b[201~"));
        assert!(!holds_more(b"\n\x1b[201~\r"));
        assert!(holds_more(b"second\x1b[201~"));
        assert!(holds_more(b"\x1b[D"));
    }

    #[test]
    fn a_typed_line_ends_at_return_and_is_edited_as_in_line_mode() {
        assert_eq!(keys(b"tok\r").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"tok\n").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"tok\x04").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"\x04").unwrap(), Typed::Ended);
        assert_eq!(keys(b"tok").unwrap(), Typed::Ended);
        assert_eq!(
            keys(b"tok one\x17two\r").unwrap(),
            Typed::Line(b"tok two".to_vec())
        );
        assert_eq!(keys(b"tok\t2\r").unwrap(), Typed::Line(b"tok\t2".to_vec()));
        assert_eq!(keys(b"tox\x7fk\r").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"bad\x15tok\r").unwrap(), Typed::Line(b"tok".to_vec()));
        // Backspace erases a whole character, not one of its bytes.
        assert_eq!(
            keys("té\x7f\r".as_bytes()).unwrap(),
            Typed::Line(b"t".to_vec())
        );
        assert_eq!(keys(b"\x7f\x7fok\r").unwrap(), Typed::Line(b"ok".to_vec()));
    }

    #[test]
    fn the_keys_that_would_signal_cancel_at_once() {
        for key in [0x03, 0x1a, 0x1c] {
            assert_eq!(keys(&[b't', key, b'x']).unwrap(), Typed::Cancelled);
            // After an Escape too, and after the start of a mark.
            assert_eq!(keys(&[0x1b, key]).unwrap(), Typed::Cancelled);
            assert_eq!(keys(&[0x1b, b'[', b'2', key]).unwrap(), Typed::Cancelled);
        }
    }

    #[test]
    fn an_escape_takes_no_more_keys_than_its_own() {
        // An arrow key in a paste does not eat the start of its end mark.
        let pasted = |bytes: &[u8]| typed(&mut bytes.iter().map(|b| Ok(*b))).unwrap();
        let mut rest = b"\x1b[200~ab\x1b[D\x1b[201~".iter().map(|b| Ok(*b));
        assert_eq!(typed(&mut rest).unwrap(), (Typed::Control(0x1b), true));
        assert_eq!(rest.map(|b| b.unwrap()).collect::<Vec<_>>(), b"\x1b[201~");
        assert_eq!(pasted(b"\x1bx"), (Typed::Control(0x1b), false));
        // A lone Escape, or a mark cut short, right before the paste's end
        // does not eat the end's own Escape.
        for cut in [&b""[..], b"[", b"[20", b"[201"] {
            let bytes = [&b"\x1b[200~a\x1b"[..], cut, b"\x1b[201~"].concat();
            assert_eq!(pasted(&bytes), (Typed::Control(0x1b), false), "{cut:?}");
        }
    }

    #[test]
    fn a_control_key_that_edits_nothing_is_refused_not_taken_in() {
        assert_eq!(keys(b"tok\x1b[D\r").unwrap(), Typed::Control(0x1b));
        assert_eq!(keys(b"tok\x12\r").unwrap(), Typed::Control(0x12));
        assert_eq!(key_name(0x12), "Ctrl-R");
        assert!(key_name(0x1b).contains("arrow"));
    }

    #[test]
    fn a_line_past_the_terminal_limit_is_read_whole_up_to_its_own() {
        let mut long = vec![b'k'; 1500];
        long.push(b'\r');
        assert_eq!(keys(&long).unwrap(), Typed::Line(vec![b'k'; 1500]));
        let too_long = vec![b'k'; MAX_TYPED + 1];
        assert_eq!(keys(&too_long).unwrap(), Typed::TooLong);
    }
}
