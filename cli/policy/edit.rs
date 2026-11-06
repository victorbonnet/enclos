//! `enclos policy edit`: the user's editor on `policy.toml`.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde_json::json;

use super::super::output;
use super::{applied_json, print_outcome, restart_failed};

use enclos::engine::{ChangeOutcome, EditFiles, Engine};
use enclos::error::{Error, Result, exit};
use enclos::layout::LayoutError;
use enclos::model::audit::Actor;
use enclos::model::plan::{Confirm, Planned};
use enclos::model::sandbox::SandboxName;

/// `policy edit`: a copy of `policy.toml` beside it, opened in the user's
/// editor, then applied. An edit kept by an earlier `policy edit` (one not
/// applied: refused, cut short, or a dry run) is opened again instead, as
/// long as `policy.toml` is still the file it started from.
pub(super) fn edit(
    engine: &Engine,
    by: &Actor,
    sandbox: &SandboxName,
    confirm: Confirm,
) -> Result<u8> {
    let file = engine.policy(sandbox)?.file;
    let files = engine.edit_files(sandbox);
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| Error::Layout(LayoutError::Io { path, source })
    };
    let current = std::fs::read_to_string(&file).map_err(io(&file))?;
    let (before, start) = match std::fs::read_to_string(&files.copy) {
        Ok(kept) => {
            let base = match std::fs::read_to_string(&files.base) {
                Ok(base) => Some(base),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(source) => return Err(io(&files.base)(source)),
            };
            // Without the file it started from, or with another one, the
            // kept edit would undo what changed since.
            if base.as_deref() != Some(current.as_str()) {
                return Err(Error::PolicyFileChanged {
                    sandbox: sandbox.to_string(),
                    file,
                });
            }
            if !output::json() {
                println!("Continuing the edit kept in {}.", files.copy.display());
            }
            (current, kept)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_private(&files.base, &current).map_err(io(&files.base))?;
            (current.clone(), current)
        }
        Err(source) => return Err(io(&files.copy)(source)),
    };
    write_private(&files.copy, &start).map_err(io(&files.copy))?;
    run_editor(&files.copy)?;
    let after = std::fs::read_to_string(&files.copy).map_err(io(&files.copy))?;
    // Saved unchanged, an edit records nothing, unless the file holds what
    // the state does not record yet: an edit not applied, such as one made
    // by hand, which closing the editor applies.
    if after == before && engine.policy_file_recorded(sandbox)? {
        let left = forget_edit(&files);
        let code = edit_left_code(&left, exit::OK);
        if output::json() {
            return Ok(output::conclude(
                json!({
                    "sandbox": sandbox.to_string(),
                    "changed": false,
                    "edit_left": left,
                }),
                code,
                || left.join("; "),
            ));
        }
        println!("No change to the policy of sandbox {sandbox}.");
        return Ok(code);
    }
    let applied = match engine.policy_edit(by, sandbox, &before, &after, confirm) {
        Ok(Planned::DryRun(plan)) => {
            if output::json() {
                let mut planned = output::plan(&plan);
                planned["edit_kept_in"] = output::path(&files.copy);
                output::emit(&planned);
                return Ok(exit::OK);
            }
            plan.changes.iter().for_each(|c| println!("Would {c}."));
            println!(
                "Your edit is kept in {}; `enclos policy edit {sandbox}` opens it again.",
                files.copy.display()
            );
            return Ok(exit::OK);
        }
        Ok(Planned::Done(applied)) => applied,
        // Recorded before it failed (a restart with --yes, say): the edit
        // is the file now, and keeping it would only open it again.
        Err(e) if std::fs::read_to_string(&file).is_ok_and(|now| now == after) => {
            let left = forget_edit(&files);
            // In JSON, what was left is said in the error's message, as
            // `edit_left` says it in a document.
            if output::json() && !left.is_empty() {
                return Err(Error::WithContext {
                    what: format!("{e}; {}", left.join("; ")),
                    error: Box::new(e),
                });
            }
            return Err(e);
        }
        Err(e @ Error::PolicyFileChanged { .. }) => return Err(e),
        Err(error) => {
            return Err(Error::WithContext {
                what: format!(
                    "{error}\nYour edit is kept in {}; `enclos policy edit {sandbox}` opens it again, and `enclos policy discard {sandbox}` drops it.",
                    files.copy.display()
                ),
                error: Box::new(error),
            });
        }
    };
    let left = forget_edit(&files);
    if output::json() {
        let (restarted, outcome) = print_outcome(engine, sandbox, &applied)?;
        let mut shown = applied_json(sandbox, &applied, outcome);
        shown["edit_left"] = json!(left);
        let code = edit_left_code(&left, restarted);
        return Ok(output::conclude(shown, code, || {
            let mut why = Vec::new();
            if restarted != exit::OK {
                why.push(restart_failed(sandbox));
            }
            why.extend(left.iter().cloned());
            why.join("; ")
        }));
    }
    let version = applied.version.version;
    match (&applied.outcome, applied.changed) {
        (ChangeOutcome::Pending(_), true) => println!(
            "Sandbox {sandbox} has policy v{version}, with the network part of the edit in force at once."
        ),
        (ChangeOutcome::Pending(_), false) => {
            println!("Sandbox {sandbox} keeps policy v{version} for now.")
        }
        (_, true) => println!(
            "Sandbox {sandbox} has policy v{version}, in force at once for the network and for sessions started from now on."
        ),
        (_, false) => println!("Sandbox {sandbox} keeps policy v{version}."),
    }
    for change in &applied.also {
        println!("  {change}");
    }
    let restarted = print_outcome(engine, sandbox, &applied)?.0;
    Ok(edit_left_code(&left, restarted))
}

/// `code`, or a failure when the edit's copy or base stays: the next `policy
/// edit` would take it up again, though the policy has changed since.
fn edit_left_code(left: &[String], code: u8) -> u8 {
    match left.is_empty() {
        true => code,
        false => code.max(exit::ERROR),
    }
}

/// Removes the copy `policy edit` edited and its base, saying so when it
/// cannot, in text: the next `policy edit` would open it again, and refuse
/// it, made from a policy that has changed since. Returns what it says, or
/// in JSON would say, for the caller to carry in its document and its
/// error; a copy left fails the command.
fn forget_edit(files: &EditFiles) -> Vec<String> {
    let mut left = Vec::new();
    for path in [&files.copy, &files.base] {
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            let said = format!(
                "could not remove {} ({e}); remove it: until then the next `enclos policy edit` opens it again, and refuses it as made from the policy before this edit",
                path.display()
            );
            if !output::json() {
                eprintln!("error: {said}");
            }
            left.push(said);
        }
    }
    left
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, contents.as_bytes()))
}

/// Opens `path` in `$VISUAL`, else `$EDITOR`, else `vi`, through `sh` so
/// that an editor given with its options (`code --wait`) works.
fn run_editor(path: &Path) -> Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(|var| std::env::var(var).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "vi".to_owned());
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(path)
        .status()
        .map_err(|e| Error::Session {
            what: format!(
                "cannot run the editor `{editor}`: {e}. Your edit is kept in {}",
                path.display()
            ),
        })?;
    if !status.success() {
        return Err(Error::Session {
            what: format!(
                "the editor `{editor}` did not exit cleanly ({status}), so nothing was applied. Your edit is kept in {}",
                path.display()
            ),
        });
    }
    Ok(())
}
