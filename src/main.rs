//! The enclos CLI: parse arguments into models, call the engine, print the
//! result. Commands follow `enclos <noun> <verb>` (design §10).

mod cli;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

use enclos::engine::{Engine, InitReport};
use enclos::error::{Result, exit};
use enclos::layout::Layout;
use enclos::model::audit::{Actor, AuditEntry, AuditResult, Since, VerifyReport};
use enclos::model::plan::{Confirm, Plan, Planned};

/// Create sandboxes, install agent runtimes in them and run agents there, with policy and an audit log.
#[derive(Parser)]
#[command(name = "enclos", version)]
struct Cli {
    /// Make changes without asking for confirmation.
    #[arg(long, global = true)]
    yes: bool,
    /// Print JSON, the result or the error, also in a terminal; the default
    /// when stdout is piped, except for `connect`, `exec` and `logs`. With
    /// it, `connect` and `exec` keep their command's output on stdout and
    /// give enclos's own messages as JSON lines on stderr (a dry run's plan
    /// is JSON on stdout); `logs` prints JSON Lines.
    #[arg(long, global = true)]
    json: bool,
    /// Print readable text, also when the output is piped; --json wins.
    #[arg(long, global = true)]
    text: bool,
    /// Show what would change, and change nothing.
    #[arg(long, global = true)]
    dry_run: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the enclos folders, state database and audit log. Safe to run again.
    Init,
    /// Say whether this host runs each backend, whether each sandbox's next session can start, and which compiled policies enclos now writes differently. Exits 1 when no backend runs, enclos's records cannot be read, or for a sandbox its backend does not run, its next session cannot compile its policy, or doctor could not look at all of it.
    Doctor,
    /// List audit entries, or verify the audit log.
    Audit(AuditArgs),
    /// Create, list, show, start, stop, restart or remove sandboxes.
    Sandbox(cli::sandbox::SandboxArgs),
    /// Open a shell, or run a command, inside a sandbox.
    Connect(cli::connect::ConnectArgs),
    /// Run one command inside a sandbox, for a script or another program; exits with its code.
    Exec(cli::connect::ExecArgs),
    /// Set, list or remove a sandbox's secrets, kept in the Keychain.
    Secret(cli::secret::SecretArgs),
    /// Check enclos's records against the host, or repair what it can.
    State(cli::state::StateArgs),
    /// Install a runtime in a sandbox, or configure the sandbox's bot on a messaging channel.
    Runtime(cli::runtime::RuntimeArgs),
    /// Add, list or remove the runtime's agents.
    Agent(cli::agent::AgentArgs),
    /// Show, widen, edit, apply, discard, refresh, diff, roll back or test a sandbox's policy, or list its history.
    Policy(cli::policy::PolicyArgs),
    /// A sandbox's network log and refused destinations.
    Net(cli::net::NetArgs),
    /// Show the logs of a sandbox's background services.
    Logs(cli::launch::LogsArgs),
    /// What is on this host, what it costs on disk, and what you could do.
    ///
    /// In JSON, sizes are in bytes, times in RFC 3339, and each fact read
    /// from a sandbox is `{"known": …}`, `"absent"`, `{"cannot_tell": why}`
    /// or `"not_provided"`.
    Status(cli::status::StatusArgs),
    /// Run one of a sandbox's runtime services; started by the service manager.
    #[command(hide = true)]
    Launch(cli::launch::LaunchArgs),
    /// Run a sandbox's egress proxy; started by enclos itself.
    #[command(hide = true)]
    Proxy(cli::proxy::ProxyArgs),
}

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
struct AuditArgs {
    #[command(subcommand)]
    verb: Option<AuditVerb>,
    /// Only entries from this far back, such as 30m, 12h, 7d or 2w.
    #[arg(long, value_name = "DURATION")]
    since: Option<Since>,
}

#[derive(Subcommand)]
enum AuditVerb {
    /// Check that no line of the audit log was edited, deleted or reordered.
    Verify,
}

fn main() -> ExitCode {
    use cli::output::Output;
    let parsed = Cli::command().try_get_matches().and_then(|matches| {
        let name = matches.subcommand_name().unwrap_or_default().to_owned();
        Cli::from_arg_matches(&matches).map(|cli| (cli, name))
    });
    let (cli, name) = match parsed {
        Ok(parsed) => parsed,
        Err(err) => return usage_error(&err),
    };
    cli::output::choose(&name, cli.json, cli.text);
    if ends_on_closed_output(&cli.command) && cli::output::output() == Output::Text {
        // Without it, the print after the reader left panics. Should the
        // handler not install, that is still what happens. Not for a JSON
        // document: its write fails instead, and `written` says what the
        // command did.
        let _ = signal_hook::flag::register_conditional_default(
            signal_hook::consts::SIGPIPE,
            Arc::new(AtomicBool::new(true)),
        );
    }
    // `exec` exits with its command's code, so its own failures take one
    // no command gives them by convention (design §10).
    let exec = matches!(cli.command, Command::Exec(_));
    let code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            let code = match exec {
                true => exit::EXEC_FAILED,
                false => err.exit_code(),
            };
            match cli::output::output() {
                Output::Text => say(&format!("error: {err}")),
                Output::Document => cli::output::emit(&cli::output::error(&err, code)),
                // Its stdout is the program's: enclos's words go to stderr.
                Output::OnStderr => say(&cli::output::line(&cli::output::error(&err, code))),
            }
            code
        }
    };
    ExitCode::from(written(code, exec))
}

/// Tells a usage error as the command would print (design §10), and exits:
/// help and version go to stdout and succeed; usage errors are errors (exit
/// 1), since exit 2 means refused by policy, or 125 for `exec`, whose 1 is
/// its command's.
fn usage_error(err: &clap::Error) -> ExitCode {
    use cli::output::Output;
    use std::io::IsTerminal;
    let words = words(std::env::args_os().skip(1));
    let command = command_word(&words).unwrap_or_default();
    let exec = command == "exec";
    let code = match err.use_stderr() {
        false => exit::OK,
        true if exec => exit::EXEC_FAILED,
        true => exit::ERROR,
    };
    let flag = |f: &str| words.iter().any(|w| w == f);
    let output = cli::output::decide(
        command,
        flag("--json"),
        flag("--text"),
        std::io::stdout().is_terminal(),
    );
    let error = || cli::output::error_text(err.render().to_string().trim(), code);
    match (code, output) {
        (exit::OK, _) | (_, Output::Text) => {
            let _ = err.print();
        }
        (_, Output::Document) => cli::output::emit(&error()),
        (_, Output::OnStderr) => say(&cli::output::line(&error())),
    }
    ExitCode::from(written(code, exec))
}

/// `code`, unless the JSON document could not be written: that is a
/// failure whatever the command did, and the message says what it did, and
/// the error the document held, so that it is not run again blindly. As
/// JSON on stderr, as enclos's notes are there.
fn written(code: u8, exec: bool) -> u8 {
    let failed = match exec {
        true => exit::EXEC_FAILED,
        false => code.max(exit::ERROR),
    };
    let who = match exec {
        true => "enclos itself",
        false => "the command itself",
    };
    let did = match code {
        exit::OK => format!("{who} succeeded"),
        code => format!("{who} failed, with exit code {code}"),
    };
    let message = match (cli::output::second_refused(), cli::output::write_failure()) {
        (true, _) => format!(
            "enclos tried to print a second JSON document, refused: a bug of enclos; the first was printed, and {did}"
        ),
        (false, Some(e)) => format!("cannot write the JSON document ({e}); {did}"),
        (false, None) => return code,
    };
    // What the document said of a failure is said here, or it is lost.
    let message = match cli::output::unsent_error() {
        Some(why) => format!("{message}: {why}"),
        None => message,
    };
    say(&cli::output::line(&cli::output::error_text(
        &message, failed,
    )));
    failed
}

/// A line on stderr. A stderr closed already never turns the exit code into
/// a panic's, as `eprintln!` would where SIGPIPE is ignored.
fn say(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

fn run(cli: Cli) -> Result<u8> {
    let engine = Engine::open(Layout::from_env()?);
    let confirm = Confirm::from_flags(cli.yes, cli.dry_run);
    match cli.command {
        Command::Init => {
            let planned = engine.init(&current_actor(), confirm)?;
            match cli::output::json() {
                true => cli::output::emit(&init_json(&planned)),
                false => print_init(planned),
            }
            Ok(exit::OK)
        }
        Command::Doctor => cli::doctor::run(&engine),
        Command::Audit(AuditArgs { verb: None, since }) => {
            let entries = engine.audit(since)?;
            match cli::output::json() {
                true => cli::output::emit(&serde_json::json!({
                    "entries": entries.iter().map(cli::output::audit_entry).collect::<Vec<_>>(),
                })),
                false => print_entries(&entries, since.is_some()),
            }
            Ok(exit::OK)
        }
        Command::Audit(AuditArgs {
            verb: Some(AuditVerb::Verify),
            ..
        }) => {
            let report = engine.verify_audit()?;
            match cli::output::json() {
                true => {
                    let code = match report.broken {
                        Some(_) => exit::ERROR,
                        None => exit::OK,
                    };
                    cli::output::emit(&cli::output::with_error(verify_json(&report), code, || {
                        format!(
                            "the audit log is broken: {}; no state-changing command runs until it is repaired: keep audit.jsonl under a name that starts with audit.jsonl, such as audit.jsonl.damaged",
                            report
                                .broken
                                .as_ref()
                                .map(ToString::to_string)
                                .unwrap_or_default()
                        )
                    }));
                    Ok(code)
                }
                false => Ok(print_verify(&report)),
            }
        }
        Command::Sandbox(args) => cli::sandbox::run(&engine, &current_actor(), confirm, args),
        Command::Connect(args) => cli::connect::run(&engine, &current_actor(), confirm, args),
        Command::Exec(args) => cli::connect::exec(&engine, &current_actor(), confirm, args),
        Command::Secret(args) => cli::secret::run(&engine, &current_actor(), confirm, args),
        Command::State(args) => cli::state::run(&engine, &current_actor(), confirm, args),
        Command::Runtime(args) => cli::runtime::run(&engine, &current_actor(), confirm, args),
        Command::Agent(args) => cli::agent::run(&engine, &current_actor(), confirm, args),
        Command::Policy(args) => cli::policy::run(&engine, &current_actor(), confirm, args),
        Command::Net(args) => cli::net::run(&engine, args),
        Command::Proxy(args) => cli::proxy::run(&engine, &current_actor(), args),
        Command::Launch(args) => cli::launch::run(&engine, &current_actor(), args),
        Command::Logs(args) => cli::launch::logs(&engine, args),
        Command::Status(args) => cli::status::run(&engine, args),
    }
}

/// Whether a reader that left early, as `head` does, ends `command`'s text
/// as it ends any Unix tool, by SIGPIPE, not by a panic on the next print.
/// In JSON the document's write fails instead, and the command says so.
/// Not for those that run the user's or a runtime's programs (`connect`,
/// `exec`, `runtime`, `agent`), keep running (`proxy`, `launch`), or handle
/// a closed output themselves (`logs`).
fn ends_on_closed_output(command: &Command) -> bool {
    matches!(
        command,
        Command::Init
            | Command::Doctor
            | Command::Audit(_)
            | Command::Sandbox(_)
            | Command::Policy(_)
            | Command::Secret(_)
            | Command::State(_)
            | Command::Net(_)
            | Command::Status(_)
    )
}

/// The words of a command line before its `--`, as text: only those can be
/// enclos's own.
fn words(args: impl Iterator<Item = std::ffi::OsString>) -> Vec<String> {
    args.map(|a| a.to_string_lossy().into_owned())
        .take_while(|a| a != "--")
        .collect()
}

/// The command a command line names: its first word that is not a flag, as
/// no flag before a command takes a value.
fn command_word(words: &[String]) -> Option<&str> {
    words
        .iter()
        .find(|w| !w.starts_with('-'))
        .map(String::as_str)
}

fn init_json(planned: &Planned<InitReport>) -> serde_json::Value {
    use cli::output::path;
    match planned {
        Planned::DryRun(plan) => cli::output::plan(plan),
        Planned::Done(report) => serde_json::json!({
            "data": path(&report.data),
            "config": path(&report.config),
            "created": report.created.iter().map(|p| path(p)).collect::<Vec<_>>(),
            "schema": {"from": report.migration.from, "to": report.migration.to},
            "default_backend": report.default_backend.map(|k| k.to_string()),
            "unavailable": report.unavailable.iter().map(|u| serde_json::json!({
                "backend": u.backend.to_string(),
                "reason": u.reason,
            })).collect::<Vec<_>>(),
            "config_names_no_backend": report.config_names_no_backend,
        }),
    }
}

fn verify_json(report: &VerifyReport) -> serde_json::Value {
    serde_json::json!({
        "intact": report.broken.is_none(),
        "lines": report.lines,
        "entries": report.entries,
        "broken": report.broken.as_ref().map(|b| serde_json::json!({
            "line": b.line,
            "problem": b.to_string(),
        })),
        "unfinished": report.unfinished.iter().map(cli::output::audit_entry).collect::<Vec<_>>(),
        "torn_tail_bytes": report.torn_tail,
        "recoveries": report.recoveries.iter().map(|r| serde_json::json!({
            "line": r.line,
            "at": r.at.to_string(),
            "removed_bytes": r.removed_bytes,
            "saved_to": r.saved_to,
        })).collect::<Vec<_>>(),
    })
}

/// The user and host recorded in audit entries.
fn current_actor() -> Actor {
    let or_unknown = |value: std::result::Result<String, _>| {
        value.unwrap_or_else(|_: whoami::Error| "unknown".to_owned())
    };
    Actor {
        user: or_unknown(whoami::username()),
        host: or_unknown(whoami::hostname()),
    }
}

fn print_init(planned: Planned<InitReport>) {
    match planned {
        Planned::DryRun(Plan { create, .. }) if create.is_empty() => {
            println!("Nothing to create: enclos is already initialized.");
        }
        Planned::DryRun(Plan { create, .. }) => {
            println!("Would create:");
            for path in create {
                println!("  {}", path.display());
            }
        }
        Planned::Done(report) => {
            let config = report.config.join("config.toml");
            if report.data == report.config {
                println!("enclos home: {}", report.data.display());
            } else {
                println!("enclos data: {}", report.data.display());
                println!("enclos configuration: {}", report.config.display());
            }
            if report.created.is_empty() && !report.migration.changed() {
                println!("Already initialized; nothing changed.");
            }
            for path in &report.created {
                println!("  created {}", path.display());
            }
            if report.migration.from > 0 && report.migration.changed() {
                println!(
                    "  upgraded state.db from schema {} to {}",
                    report.migration.from, report.migration.to
                );
            }
            match report.default_backend {
                Some(kind) if report.created.contains(&config) => {
                    println!("Default backend: {kind}.");
                }
                Some(kind) if report.config_names_no_backend => println!(
                    "{} names no default backend, though {kind} is available now: it was written while none was. Add `default_backend = \"{kind}\"` to it.",
                    config.display()
                ),
                Some(_) => {}
                // Said at every run, with why, so that a setting that turned
                // a backend off is seen at once, not at the first create.
                None => {
                    println!("No backend is available on this host yet:");
                    for u in &report.unavailable {
                        println!("  {}: {}", u.backend, u.reason);
                    }
                }
            }
        }
    }
}

fn print_entries(entries: &[AuditEntry], filtered: bool) {
    if entries.is_empty() {
        let scope = if filtered { " in that period" } else { "" };
        println!("No audit entries{scope}.");
        return;
    }
    let rows: Vec<[String; 5]> = entries.iter().map(row).collect();
    let header = ["LINE", "TIME (UTC)", "BY", "COMMAND", "RESULT"].map(str::to_owned);
    let mut widths = [0; 4];
    for cells in std::iter::once(&header).chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(cells) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for [seq, at, by, command, result] in std::iter::once(&header).chain(&rows) {
        let [w0, w1, w2, w3] = widths;
        println!("{seq:>w0$}  {at:<w1$}  {by:<w2$}  {command:<w3$}  {result}");
    }
}

fn row(entry: &AuditEntry) -> [String; 5] {
    let intent = &entry.intent;
    let command = match &intent.target {
        Some(target) => format!("{} {target}", intent.command),
        None => intent.command.clone(),
    };
    let result = match &entry.finished {
        None => "unfinished".to_owned(),
        Some(finished) => {
            let result = match finished.outcome.result {
                AuditResult::Ok => "ok",
                AuditResult::Failed => "failed",
            };
            format!("{result}: {}", finished.outcome.message)
        }
    };
    [
        entry.seq.to_string(),
        entry.at.strftime("%Y-%m-%d %H:%M:%S").to_string(),
        format!("{}@{}", intent.by.user, intent.by.host),
        command,
        result,
    ]
}

fn print_verify(report: &VerifyReport) -> u8 {
    if let Some(broken) = &report.broken {
        eprintln!("error: the audit log is broken: {broken}.");
        eprintln!(
            "Entries from line {} on cannot be trusted, and no state-changing command runs \
             until the log is repaired.",
            broken.line
        );
        eprintln!(
            "To repair it, rename audit.jsonl and keep it to investigate: a name that starts \
             with audit.jsonl, such as audit.jsonl.damaged, stays hidden from sandboxes. The \
             next state-changing command then starts a new chain."
        );
        return exit::ERROR;
    }
    println!(
        "Audit log intact: {} lines, {} entries, hash chain verified.",
        report.lines, report.entries
    );
    if !report.unfinished.is_empty() {
        let count = report.unfinished.len();
        let entries = if count == 1 { "entry" } else { "entries" };
        println!(
            "warning: {count} {entries} never finished; enclos may have stopped in the middle of:"
        );
        for entry in &report.unfinished {
            let [seq, at, by, command, _] = row(entry);
            println!("  line {seq}  {at}  {by}  {command}");
        }
    }
    if let Some(bytes) = report.torn_tail {
        println!(
            "warning: the last line is incomplete ({bytes} bytes), as when enclos stops while writing it. \
             The next command moves it aside and records that in the log."
        );
    }
    for recovery in &report.recoveries {
        println!(
            "note: line {}, {}: an incomplete line of {} bytes was moved to {}.",
            recovery.line,
            recovery.at.strftime("%Y-%m-%d %H:%M:%S"),
            recovery.removed_bytes,
            recovery.saved_to
        );
    }
    exit::OK
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    /// The word a command group's one-line description uses for a verb
    /// whose name it does not spell out.
    fn said_as(verb: &str) -> &str {
        match verb {
            "rm" => "remove",
            "allow" => "widen",
            "denied" => "refused",
            "rollback" => "roll",
            verb => verb,
        }
    }

    /// Whether `about` has `word` as a whole word, so "restart" does not
    /// count as "start".
    fn names(about: &str, word: &str) -> bool {
        about
            .split(|c: char| !c.is_alphanumeric() && c != '-')
            .any(|w| w == word)
    }

    #[test]
    fn a_command_line_names_its_command_by_its_first_word() {
        let w = |words: &[&str]| super::words(words.iter().map(std::ffi::OsString::from));
        assert_eq!(super::command_word(&w(&["exec", "lab"])), Some("exec"));
        assert_eq!(super::command_word(&w(&["--yes", "exec"])), Some("exec"));
        assert_eq!(super::command_word(&w(&["--"])), None);
        assert_eq!(super::command_word(&w(&[])), None);
        // What follows `--` is the command's, not enclos's.
        assert_eq!(w(&["exec", "lab", "--", "--json"]), ["exec", "lab"]);
        assert_eq!(
            super::command_word(&w(&["connect", "lab", "--", "exec"])),
            Some("connect")
        );
    }

    /// The commands whose stdout is a program's are named by words that are
    /// commands, so a renamed one is not left printing JSON on its stdout.
    #[test]
    fn the_commands_that_run_a_program_are_commands() {
        let cli = Cli::command();
        let names: Vec<&str> = cli.get_subcommands().map(|c| c.get_name()).collect();
        for word in super::cli::output::RUNS_A_PROGRAM {
            assert!(names.contains(&word), "{word} is no command");
        }
    }

    /// No argument before the command takes a value, so its first word that
    /// is not a flag is the command, as `command_word` reads it.
    #[test]
    fn no_global_argument_takes_a_value() {
        let cli = Cli::command();
        for arg in cli.get_arguments() {
            assert!(
                !arg.get_action().takes_values(),
                "--{} takes a value: `command_word` would read it as the command",
                arg.get_id()
            );
        }
    }

    #[test]
    fn a_verb_counts_only_as_a_whole_word() {
        assert!(names("create, start or restart sandboxes.", "start"));
        assert!(!names("create, stop or restart sandboxes.", "start"));
        assert!(!names("shows a sandbox.", "show"));
    }

    #[test]
    fn each_command_group_description_names_every_verb() {
        let cli = Cli::command();
        for group in cli.get_subcommands().filter(|c| !c.is_hide_set()) {
            let about = group
                .get_about()
                .map(|a| a.to_string().to_lowercase())
                .unwrap_or_default();
            for verb in group.get_subcommands().filter(|c| !c.is_hide_set()) {
                let word = said_as(verb.get_name());
                assert!(
                    names(&about, word),
                    "`{}`: {about:?} does not say {word:?}",
                    group.get_name()
                );
            }
        }
    }
}
