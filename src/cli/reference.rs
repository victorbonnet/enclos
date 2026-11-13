//! The enclos plugin's references, rendered from their one source each, so
//! that a host assistant reads what this build does and a change that
//! forgets them fails here:
//!
//! - `commands.md`, from the CLI's own definitions (`Cli::command()`): every
//!   command a user may run, its usage, arguments and options, the global
//!   options and the exit codes. Hidden commands, which enclos runs itself,
//!   are left out.
//! - `policy.md`, from `docs/policy-compilation.md`'s sections on the
//!   templates and every setting.
//!
//! `ENCLOS_WRITE_SNAPSHOTS=1 cargo test --bin enclos reference` writes them
//! again.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, Command, CommandFactory};

use enclos::error::exit;

const SKILL: &str = "plugins/enclos/skills/enclos/reference";

/// What each exit code means, for every code in `enclos::error::exit`.
const EXIT_CODES: [(u8, &str); 5] = [
    (exit::OK, "Done; or, for a check, nothing found."),
    (
        exit::ERROR,
        "An error, or a check that found something, such as `doctor`, `state check` or a `policy test` with a failed probe.",
    ),
    (
        exit::REFUSED,
        "Refused: a policy whose problems are all refusals, or a backend this host cannot run. Nothing changed.",
    ),
    (
        exit::NEEDS_CONFIRMATION,
        "Needs confirmation: run it again with `--yes` to make the change, or with `--dry-run` to see the plan first. enclos never prompts for it.",
    ),
    (
        exit::EXEC_FAILED,
        "`enclos exec` failed before, around or after its command; otherwise `exec` exits with its command's own code.",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// `commands.md`: the whole CLI, as a host assistant reads it.
pub fn commands() -> String {
    let mut cli = crate::Cli::command();
    cli.build();
    let mut out = String::new();
    let _ = writeln!(out, "# enclos commands");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Every command of enclos {}, rendered from its own definitions; `enclos <command> --help` says the same. When `enclos --version` prints another version, read `--help` instead of this file.",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", about(&cli));
    let _ = writeln!(out);
    let _ = writeln!(out, "## Global options");
    let _ = writeln!(out);
    let _ = writeln!(out, "Every command takes these.");
    let _ = writeln!(out);
    for arg in cli.get_arguments().filter(|a| shown(a)) {
        let _ = writeln!(out, "{}", item(arg));
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Exit codes");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Code | Meaning |");
    let _ = writeln!(out, "| --- | --- |");
    for (code, meaning) in EXIT_CODES {
        let _ = writeln!(out, "| {code} | {meaning} |");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Commands");
    for sub in cli.get_subcommands().filter(|c| listed(c)) {
        command(&mut out, sub);
    }
    out
}

/// One command, then its own subcommands, one heading level down each.
fn command(out: &mut String, cmd: &Command) {
    let name = cmd.get_bin_name().unwrap_or(cmd.get_name());
    let depth = name.split(' ').count().min(5) + 1;
    let _ = writeln!(out);
    let _ = writeln!(out, "{} `{name}`", "#".repeat(depth));
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", about(cmd));
    let subs: Vec<&Command> = cmd.get_subcommands().filter(|c| listed(c)).collect();
    let args: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|a| shown(a) && !a.is_global_set())
        .collect();
    // A group shows its usage only when it takes arguments of its own, as
    // `audit` does beside `audit verify`.
    if subs.is_empty() || !args.is_empty() {
        let usage = cmd.clone().render_usage().to_string();
        let usage = usage
            .trim_start_matches("Usage: ")
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n");
        let _ = writeln!(out);
        let _ = writeln!(out, "```text\n{usage}\n```");
    }
    if !args.is_empty() {
        let _ = writeln!(out);
        for arg in args {
            let _ = writeln!(out, "{}", item(arg));
        }
    }
    for sub in subs {
        command(out, sub);
    }
}

/// A command a user may run: not hidden, and not clap's own `help`, which
/// says what `--help` says.
fn listed(cmd: &Command) -> bool {
    !cmd.is_hide_set() && cmd.get_name() != "help"
}

/// An argument a user may give: not hidden, and not clap's own help or
/// version.
fn shown(arg: &Arg) -> bool {
    !arg.is_hide_set() && !matches!(arg.get_id().as_str(), "help" | "version")
}

fn about(cmd: &Command) -> String {
    cmd.get_long_about()
        .or(cmd.get_about())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// One argument as a list item: its spelling, its help, and its values.
fn item(arg: &Arg) -> String {
    let help = arg
        .get_long_help()
        .or(arg.get_help())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let help = help.replace("\n\n", " ").replace('\n', " ");
    let mut line = format!("- `{arg}`");
    if !help.is_empty() {
        let _ = write!(line, ": {help}");
        if !help.ends_with(['.', '!', '?', ')']) {
            line.push('.');
        }
    }
    let values: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| format!("`{}`", v.get_name()))
        .collect();
    if !values.is_empty() && arg.get_action().takes_values() {
        let _ = write!(line, " One of {}.", values.join(", "));
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| format!("`{}`", v.to_string_lossy()))
        .collect();
    if !defaults.is_empty() && arg.get_action().takes_values() {
        let _ = write!(line, " Default: {}.", defaults.join(", "));
    }
    line
}

/// `policy.md`: the templates and every policy setting, cut from
/// `docs/policy-compilation.md`, with links into the rest of the docs made
/// absolute so they still lead somewhere from the plugin.
pub fn policy() -> String {
    let doc = std::fs::read_to_string(root().join("docs/policy-compilation.md")).unwrap();
    let mut out = String::from(
        "# Policy: the templates and every setting\n\nFrom `docs/policy-compilation.md` in enclos's repository, as of enclos ",
    );
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str(
        ". Read a sandbox's own policy with `enclos policy show <sandbox>`; widen it with `enclos policy allow`, or edit it with `enclos policy edit` and `enclos policy apply`.\n",
    );
    for heading in ["## The templates", "## Every setting"] {
        out.push('\n');
        out.push_str(&absolute_links(section(&doc, heading)));
    }
    out
}

/// The section under a `## ` heading, the heading included, up to the next
/// `## ` heading.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("docs/policy-compilation.md has no {heading:?}"))
        + 1;
    let end = doc[start + heading.len()..]
        .find("\n## ")
        .map_or(doc.len(), |i| start + heading.len() + i + 1);
    &doc[start..end]
}

/// Relative links of `docs/` (`](adr/…)`, `](design.md#…)`, `](#…)`) become
/// links to the repository on GitHub, since the plugin holds neither the
/// other files nor the rest of this one.
fn absolute_links(text: &str) -> String {
    const BASE: &str = "https://github.com/victorbonnet/enclos/blob/main/docs/";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("](") {
        out.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
        if rest.starts_with('#') {
            out.push_str(BASE);
            out.push_str("policy-compilation.md");
        } else if !rest.starts_with("http") {
            let target = rest.strip_prefix("../").map_or_else(
                || BASE.to_string(),
                |_| BASE.trim_end_matches("docs/").to_string(),
            );
            out.push_str(&target);
            rest = rest.strip_prefix("../").unwrap_or(rest);
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(file: &str, got: &str) {
        let path = root().join(SKILL).join(file);
        if std::env::var_os("ENCLOS_WRITE_SNAPSHOTS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, got).unwrap();
            return;
        }
        let want = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            got == want,
            "{} is out of date: run `ENCLOS_WRITE_SNAPSHOTS=1 cargo test --bin enclos reference` and commit it",
            path.display()
        );
    }

    #[test]
    fn the_command_reference_is_current() {
        check("commands.md", &commands());
    }

    #[test]
    fn the_policy_reference_is_current() {
        check("policy.md", &policy());
    }

    #[test]
    fn hidden_commands_stay_out() {
        let text = commands();
        for hidden in [
            "`enclos inside",
            "`enclos launch",
            "`enclos proxy",
            "`enclos relay",
        ] {
            assert!(!text.contains(hidden), "{hidden}");
        }
        assert!(!text.contains("`enclos sandbox help"));
        assert!(text.contains("#### `enclos sandbox create`"));
    }

    #[test]
    fn links_into_the_docs_become_absolute() {
        assert_eq!(
            absolute_links(
                "see [ADR 9](adr/0009-x.md), [this](#every-setting), [r](../README.md) and [w](https://x)"
            ),
            "see [ADR 9](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0009-x.md), [this](https://github.com/victorbonnet/enclos/blob/main/docs/policy-compilation.md#every-setting), [r](https://github.com/victorbonnet/enclos/blob/main/README.md) and [w](https://x)"
        );
    }
}
