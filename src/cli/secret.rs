//! `enclos secret`: set, list or remove a sandbox's secrets (design §12,
//! ADR 0022). A value is read from the input, never from the command line,
//! which other processes can list.

use std::io::{IsTerminal, Read, Write};

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
        // What came past the line, such as more pasted lines, is dropped
        // before echo comes back, so the shell never reads it as commands.
        // Either call failing counts as more having come.
        let more = rustix::io::ioctl_fionread(&stdin).map_or(true, |n| n > 0);
        let flushed =
            rustix::termios::tcflush(&stdin, rustix::termios::QueueSelector::IFlush).is_ok();
        quiet.restore();
        eprintln!();
        match typed.map_err(io)? {
            Typed::Cancelled => {
                return Err(Error::Session {
                    what: format!("cancelled: secret {secret} was not set"),
                });
            }
            Typed::TooLong => {
                return Err(refused(&format!(
                    "a value typed at a terminal is at most {MAX_TYPED} bytes; pipe a longer one in"
                )));
            }
            Typed::Line(_) if more || !flushed => {
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
    /// More than [`MAX_TYPED`] bytes.
    TooLong,
}

/// A line from `keys`, as a terminal in line mode would make it, but with
/// no limit of its own: Return or Ctrl-D ends it, Backspace erases a
/// character and Ctrl-U the line, and the keys that would signal cancel it
/// at once.
fn typed(keys: &mut impl Iterator<Item = std::io::Result<u8>>) -> std::io::Result<Typed> {
    let mut line = Vec::new();
    for key in keys {
        match key? {
            b'\r' | b'\n' | 0x04 => return Ok(Typed::Line(line)),
            0x03 | 0x1a | 0x1c => return Ok(Typed::Cancelled),
            // A character's last byte, and any continuation bytes before it.
            0x7f | 0x08 => {
                while let Some(byte) = line.pop() {
                    if byte & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            0x15 => line.clear(),
            _ if line.len() == MAX_TYPED => return Ok(Typed::TooLong),
            byte => line.push(byte),
        }
    }
    Ok(Typed::Line(line))
}

/// The terminal with echo, line mode and its signal keys off while it
/// lives: [`typed`] makes the line, so the terminal's own line limit does
/// not apply, and Ctrl-C ends the read at once rather than enclos, which
/// would leave echo off.
struct Quiet<'a> {
    stdin: &'a std::io::Stdin,
    before: Option<rustix::termios::Termios>,
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
        Ok(Quiet {
            stdin,
            before: Some(before),
        })
    }

    /// Puts the terminal back as it was, saying so when it cannot.
    fn restore(mut self) {
        self.put_back();
    }

    fn put_back(&mut self) {
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
        typed(&mut bytes.iter().map(|b| Ok(*b)))
    }

    #[test]
    fn a_typed_line_ends_at_return_and_is_edited_as_in_line_mode() {
        assert_eq!(keys(b"tok\r").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"tok\n").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"tok\x04").unwrap(), Typed::Line(b"tok".to_vec()));
        assert_eq!(keys(b"tok").unwrap(), Typed::Line(b"tok".to_vec()));
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
        }
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
