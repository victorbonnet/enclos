//! `enclos secret`: set, list or remove a sandbox's secrets (design §12,
//! ADR 0022). A value is read from the input, never from the command line,
//! which other processes can list.

use std::io::{BufRead, IsTerminal, Write};

use clap::{Args, Subcommand};

use enclos::engine::{Engine, SecretSet, SecretView};
use enclos::error::{Error, Result, exit};
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;
use enclos::model::secret::SecretRef;

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    verb: SecretVerb,
}

#[derive(Subcommand)]
enum SecretVerb {
    /// Store a secret of a sandbox in the Keychain, reading its value from
    /// the input (typed without echo at a terminal).
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
                Confirm::DryRun => "-".to_owned(),
                _ => read_value(&secret)?,
            };
            match engine.secret_set(by, &secret, &value, confirm)? {
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

/// The value from the input: one line, its line ending left out. At a
/// terminal it asks, with echo off, so the value never shows on screen.
fn read_value(secret: &SecretRef) -> Result<String> {
    let stdin = std::io::stdin();
    let io = |e: std::io::Error| Error::Session {
        what: format!("cannot read the value of secret {secret}: {e}"),
    };
    let mut line = String::new();
    if stdin.is_terminal() {
        eprint!("Value of secret {secret} (not shown): ");
        let _ = std::io::stderr().flush();
        let echo = EchoOff::new(&stdin).map_err(io)?;
        let read = stdin.lock().read_line(&mut line);
        drop(echo);
        eprintln!();
        read.map_err(io)?;
    } else {
        stdin.lock().read_line(&mut line).map_err(io)?;
    }
    let value = line
        .strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(&line);
    Ok(value.to_owned())
}

/// The terminal's echo turned off while it lives.
struct EchoOff<'a> {
    stdin: &'a std::io::Stdin,
    before: rustix::termios::Termios,
}

impl<'a> EchoOff<'a> {
    fn new(stdin: &'a std::io::Stdin) -> std::io::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let before = tcgetattr(stdin)?;
        let mut quiet = before.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(stdin, OptionalActions::Now, &quiet)?;
        Ok(EchoOff { stdin, before })
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.stdin,
            rustix::termios::OptionalActions::Now,
            &self.before,
        );
    }
}

fn print_set(secret: &SecretRef, set: &SecretSet) {
    match set.new {
        true => println!("Stored secret {secret} in the Keychain."),
        false => println!("Replaced the value of secret {secret} in the Keychain."),
    }
    let sandbox = &secret.sandbox;
    match set.granted_as.as_slice() {
        [] => println!(
            "No session gets it until the policy grants it: `enclos policy edit {sandbox}`, under [secrets], as `env = {{ NAME = \"{}\" }}`.",
            secret.in_policy()
        ),
        variables => {
            let shown: Vec<String> = variables.iter().map(|v| format!("${v}")).collect();
            println!(
                "Sessions started from now on get it as {}.",
                shown.join(", ")
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
