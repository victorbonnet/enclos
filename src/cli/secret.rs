//! `enclos secret`: set, list or remove a sandbox's secrets (design §12,
//! ADR 0022). A value is read from the input, never from the command line,
//! which other processes can list.

use std::io::{BufRead, IsTerminal, Read, Write};

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
const MAX_INPUT: u64 = 1 << 20;

/// The value from the input. At a terminal it asks for one line, with echo
/// off, so the value never shows on screen; piped in, it is all the input,
/// so a value of several lines (a PEM file) comes whole.
fn read_value(secret: &SecretRef) -> Result<SecretValue> {
    let stdin = std::io::stdin();
    let io = |e: std::io::Error| Error::Session {
        what: format!("cannot read the value of secret {secret}: {e}"),
    };
    let text = if stdin.is_terminal() {
        eprint!("Value of secret {secret} (not shown): ");
        let _ = std::io::stderr().flush();
        let quiet = Quiet::new(&stdin).map_err(io)?;
        let mut line = String::new();
        let read = stdin.lock().read_line(&mut line);
        // What was pasted past the first line is dropped before echo comes
        // back, so the shell never reads it as commands.
        let more = rustix::io::ioctl_fionread(&stdin).unwrap_or(0) > 0;
        let _ = rustix::termios::tcflush(&stdin, rustix::termios::QueueSelector::IFlush);
        quiet.restore();
        eprintln!();
        read.map_err(io)?;
        if line.contains(['\u{3}', '\u{1a}']) {
            return Err(Error::Session {
                what: format!("cancelled: secret {secret} was not set"),
            });
        }
        if more {
            return Err(Error::Session {
                what: format!(
                    "the value of secret {secret} came with more lines, which were dropped: at a terminal a value is one line; pipe in one of several lines"
                ),
            });
        }
        line
    } else {
        let mut text = String::new();
        stdin
            .lock()
            .take(MAX_INPUT)
            .read_to_string(&mut text)
            .map_err(io)?;
        text
    };
    let value = text
        .strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(&text);
    SecretValue::new(value.to_owned()).map_err(|e| Error::Session {
        what: format!("secret {secret} was not set: {e}"),
    })
}

/// The terminal with echo and its signal keys off while it lives: Ctrl-C
/// then ends the line rather than enclos, which would leave echo off.
struct Quiet<'a> {
    stdin: &'a std::io::Stdin,
    before: Option<rustix::termios::Termios>,
}

impl<'a> Quiet<'a> {
    fn new(stdin: &'a std::io::Stdin) -> std::io::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let before = tcgetattr(stdin)?;
        let mut quiet = before.clone();
        quiet
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ISIG);
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
