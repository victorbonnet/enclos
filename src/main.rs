//! The enclos CLI: parse arguments into models, call the engine, print the
//! result. Commands follow `enclos <noun> <verb>` (design §10).

mod cli;

use std::process::ExitCode;

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
    /// List audit entries, or verify the audit log.
    Audit(AuditArgs),
    /// Create, list, show, stop or remove sandboxes.
    Sandbox(cli::sandbox::SandboxArgs),
    /// Open a shell, or run a command, inside a sandbox.
    Connect(cli::connect::ConnectArgs),
    /// Show or change a sandbox's policy.
    Policy(cli::policy::PolicyArgs),
    /// A sandbox's network log and refused destinations.
    Net(cli::net::NetArgs),
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
            let _ = err.print();
            // Help and version go to stdout and succeed; usage errors are
            // errors (exit 1), since exit 2 means refused by policy.
            return ExitCode::from(if err.use_stderr() {
                exit::ERROR
            } else {
                exit::OK
            });
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let engine = Engine::open(Layout::from_env()?);
    let confirm = Confirm::from_flags(cli.yes, cli.dry_run);
    match cli.command {
        Command::Init => {
            print_init(engine.init(&current_actor(), confirm)?);
            Ok(exit::OK)
        }
        Command::Audit(AuditArgs { verb: None, since }) => {
            print_entries(&engine.audit(since)?, since.is_some());
            Ok(exit::OK)
        }
        Command::Audit(AuditArgs {
            verb: Some(AuditVerb::Verify),
            ..
        }) => Ok(print_verify(&engine.verify_audit()?)),
        Command::Sandbox(args) => cli::sandbox::run(&engine, &current_actor(), confirm, args),
        Command::Connect(args) => cli::connect::run(&engine, &current_actor(), confirm, args),
        Command::Policy(args) => cli::policy::run(&engine, &current_actor(), confirm, args),
        Command::Net(args) => cli::net::run(&engine, args),
        Command::Proxy(args) => cli::proxy::run(&engine, args),
    }
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
            "Entries from line {} on cannot be trusted. Keep a copy of audit.jsonl to investigate.",
            broken.line
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
