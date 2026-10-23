//! The enclos CLI: parse arguments into models, call the engine, print the
//! result. Commands follow `enclos <noun> <verb>` (design §10).

mod cli;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::{Args, Parser, Subcommand};

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
    /// when the output is piped, but for `connect`, `exec` and `logs`, whose
    /// output is their program's.
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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // Help and version go to stdout and succeed; usage errors are
            // errors (exit 1), since exit 2 means refused by policy, or 125
            // for `exec`, whose 1 is its command's.
            let code = match err.use_stderr() {
                false => exit::OK,
                true if names_exec(std::env::args_os().skip(1)) => exit::EXEC_FAILED,
                true => exit::ERROR,
            };
            let words = words(std::env::args_os().skip(1));
            use std::io::IsTerminal;
            let error = || cli::output::error_text(err.render().to_string().trim(), code);
            match (code, usage_as(&words, std::io::stdout().is_terminal())) {
                (exit::OK, _) | (_, Usage::Text) => {
                    let _ = err.print();
                }
                (_, Usage::JsonOnStdout) => cli::output::emit(&error()),
                (_, Usage::JsonOnStderr) => eprintln!("{}", cli::output::line(&error())),
            }
            return ExitCode::from(code);
        }
    };
    let owns_output = runs_a_program(&cli.command);
    if cli::output::choose(cli.json, cli.text, !owns_output) == cli::output::Format::Json
        && !owns_output
    {
        cli::output::keep_stdout_for_the_document();
    }
    if ends_on_closed_output(&cli.command) {
        // Without it, the print after the reader left panics. Should the
        // handler not install, that is still what happens.
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
            match (cli::output::json(), owns_output) {
                (false, _) => eprintln!("error: {err}"),
                (true, false) => cli::output::emit(&cli::output::error(&err, code)),
                // Its stdout is the program's: enclos's words go to stderr.
                (true, true) => eprintln!("{}", cli::output::line(&cli::output::error(&err, code))),
            }
            code
        }
    };
    // A document that could not be written is a failure, whatever the
    // command did.
    if let Some(e) = cli::output::write_failure() {
        eprintln!("error: cannot write the JSON document: {e}");
        return ExitCode::from(match exec {
            true => exit::EXEC_FAILED,
            false => code.max(exit::ERROR),
        });
    }
    ExitCode::from(code)
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

/// Whether a reader that left early, as `head` does, ends `command` as it
/// ends any Unix tool, by SIGPIPE, not by a panic on the next print. Not for
/// those that run the user's or a runtime's programs (`connect`, `runtime`,
/// `agent`), keep running (`proxy`, `launch`), or handle a closed output
/// themselves (`logs`).
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

/// Whether `command` runs a program whose output is its own, so that its
/// stdout is the program's: not JSON when piped, and with `--json` only a
/// dry run's plan is enclos's JSON there (design §10).
fn runs_a_program(command: &Command) -> bool {
    matches!(
        command,
        Command::Connect(_)
            | Command::Exec(_)
            | Command::Logs(_)
            | Command::Launch(_)
            | Command::Proxy(_)
    )
}

/// How a usage error is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Usage {
    Text,
    JsonOnStdout,
    JsonOnStderr,
}

/// The words of a command line before its `--`, as text: only those can be
/// enclos's own.
fn words(args: impl Iterator<Item = std::ffi::OsString>) -> Vec<String> {
    args.map(|a| a.to_string_lossy().into_owned())
        .take_while(|a| a != "--")
        .collect()
}

/// How a usage error of the command line `words` is told, as a parsed one
/// would print (design §10): JSON with `--json`, or piped without `--text`;
/// for a command that runs a program, as [`runs_a_program`] says, of its
/// first word that is not a flag, JSON only with `--json`, and on stderr.
fn usage_as(words: &[String], stdout_is_terminal: bool) -> Usage {
    let flag = |f: &str| words.iter().any(|w| w == f);
    let runs = words
        .iter()
        .find(|w| !w.starts_with('-'))
        .is_some_and(|w| matches!(w.as_str(), "connect" | "exec" | "logs" | "launch" | "proxy"));
    match (runs, flag("--json"), flag("--text") || stdout_is_terminal) {
        (true, true, _) => Usage::JsonOnStderr,
        (true, false, _) => Usage::Text,
        (false, true, _) | (false, false, false) => Usage::JsonOnStdout,
        (false, false, true) => Usage::Text,
    }
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

/// Whether `args`, the command line after the program, run `exec`: its
/// first word that is not a flag, as no flag before a command takes a
/// value.
fn names_exec(mut args: impl Iterator<Item = std::ffi::OsString>) -> bool {
    args.find(|a| !a.to_string_lossy().starts_with('-'))
        .is_some_and(|a| a == "exec")
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
            if report.created.contains(&config) {
                match report.default_backend {
                    Some(kind) => println!("Default backend: {kind}."),
                    None => println!("No backend is available on this host yet."),
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
    fn a_usage_error_of_exec_is_told_from_other_commands() {
        let args = |words: &[&str]| {
            words
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(super::names_exec(args(&["exec", "lab"]).into_iter()));
        assert!(super::names_exec(args(&["--yes", "exec"]).into_iter()));
        assert!(!super::names_exec(
            args(&["connect", "lab", "--", "exec"]).into_iter()
        ));
        assert!(!super::names_exec(args(&[]).into_iter()));
    }

    #[test]
    fn a_usage_error_is_told_as_the_command_would_print() {
        use super::{Usage, usage_as};
        let w = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        assert_eq!(usage_as(&w(&["sandbox", "x"]), false), Usage::JsonOnStdout);
        assert_eq!(usage_as(&w(&["sandbox", "x"]), true), Usage::Text);
        assert_eq!(
            usage_as(&w(&["--json", "sandbox"]), true),
            Usage::JsonOnStdout
        );
        assert_eq!(usage_as(&w(&["--text", "sandbox"]), false), Usage::Text);
        assert_eq!(
            usage_as(&w(&["--text", "--json", "x"]), false),
            Usage::JsonOnStdout
        );
        // A command whose output is its program's: JSON only when asked,
        // and on stderr.
        assert_eq!(usage_as(&w(&["exec", "lab"]), false), Usage::Text);
        assert_eq!(usage_as(&w(&["--yes", "exec"]), false), Usage::Text);
        assert_eq!(
            usage_as(&w(&["--json", "logs"]), false),
            Usage::JsonOnStderr
        );
        // What follows `--` is the command's, not enclos's.
        assert_eq!(
            super::words(
                ["exec", "lab", "--", "--json"]
                    .iter()
                    .map(std::ffi::OsString::from)
            ),
            ["exec", "lab"]
        );
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
