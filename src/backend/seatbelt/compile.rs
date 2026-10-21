//! Compiling a policy for Seatbelt (design §5): `(allow default)`,
//! then writes only where granted, reads of the sandbox home, the sensitive
//! deny list for reads and writes (after those allows, so no grant covers
//! it), network only to the sandbox's proxy port, the host-service denials,
//! and last, so no rule above can override them, enclos's protected paths
//! and the home and workspaces themselves, which stay where they are.
//!
//! Seatbelt matches real paths, so every path is resolved first (`/tmp` is
//! `/private/tmp` on macOS). Every denial carries the sandbox's tag, which
//! the unified log repeats, to tell sandboxes apart.

use std::path::{Path, PathBuf};

use super::super::{CompileError, Compiled, SandboxContext};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::policy::paths::{PathContext, is_within, real_path};

const HOST_SERVICES: &str = include_str!("host-services.sb");

/// Device files every runtime writes to (shown by the prototype: shells,
/// Python, Node and Hermes).
const DEVICES: &[&str] = &[
    "(literal \"/dev/null\")",
    "(literal \"/dev/zero\")",
    "(literal \"/dev/random\")",
    "(literal \"/dev/urandom\")",
    "(literal \"/dev/tty\")",
    "(literal \"/dev/ptmx\")",
    "(literal \"/dev/dtracehelper\")",
    "(regex #\"^/dev/ttys[0-9]+$\")",
    "(regex #\"^/dev/fd/[0-9]+$\")",
];

/// The tag a sandbox's denials carry in the unified log.
pub fn tag(ctx: &SandboxContext) -> String {
    format!("enclos:{}", ctx.name)
}

pub fn compile(policy: &Policy, ctx: &SandboxContext) -> Result<Compiled, CompileError> {
    let tag = tag(ctx);
    let paths = PathContext {
        user_home: ctx.user_home.clone(),
        sandbox_home: ctx.home.clone(),
    };
    let expand = |entries: &[String]| -> Result<Vec<PathBuf>, CompileError> {
        entries
            .iter()
            .map(|e| paths.expand(e).map(|p| real_path(&p)).map_err(unsupported))
            .collect()
    };
    let home = real_path(&ctx.home);
    let writes = expand(&policy.fs.write)?;
    let read_deny = expand(&policy.fs.read_deny)?;

    let mut sb = String::new();
    let mut line = |text: String| {
        sb.push_str(&text);
        sb.push('\n');
    };
    line(format!(
        ";; enclos compiled policy for sandbox {}. Generated: edit policy.toml instead.",
        ctx.name
    ));
    line("(version 1)".into());
    line("(allow default)".into());

    line("\n;; ---- Writes: the sandbox home, granted workspaces and device files".into());
    line(format!("(deny file-write* (with message \"{tag}\"))"));
    let mut allowed = vec![subpath(&home)?];
    for path in &writes {
        allowed.push(subpath(path)?);
    }
    allowed.extend(DEVICES.iter().map(|d| d.to_string()));
    line(format!("(allow file-write*\n  {})", allowed.join("\n  ")));

    line(format!("(allow file-read* {})", subpath(&home)?));

    line(
        "\n;; ---- Sensitive paths: neither read nor written, whatever a grant covers (ADR 0015)"
            .into(),
    );
    if !read_deny.is_empty() {
        let denied = read_deny
            .iter()
            .map(|p| {
                // An entry holding the home leaves the home out: later rules
                // win, and the sandbox must keep its home.
                if is_within(&home, p) {
                    Ok(format!(
                        "(require-all {} (require-not {}))",
                        subpath(p)?,
                        subpath(&home)?
                    ))
                } else {
                    subpath(p)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        line(format!(
            "(deny file-read* file-write* (with message \"{tag}\")\n  {})",
            denied.join("\n  ")
        ));
    }

    line(
        "\n;; ---- Network: only the sandbox's proxy, and Unix sockets in its home (ADR 0007)"
            .into(),
    );
    line(format!("(deny network* (with message \"{tag}\"))"));
    line(format!(
        "(allow network-outbound (remote ip \"localhost:{}\"))",
        ctx.proxy_port
    ));
    line(format!(
        "(allow network-bind network-inbound (local unix-socket {}))",
        subpath(&home)?
    ));
    line(format!(
        "(allow network-outbound (remote unix-socket {}))",
        subpath(&home)?
    ));

    line(String::new());
    line(HOST_SERVICES.replace("{tag}", &tag).trim_end().to_owned());

    line("\n;; ---- enclos's own files, whatever the policy says (ADR 0010)".into());
    for root in &ctx.protected {
        line(format!(
            "(deny file-write* (with message \"{tag}\")\n  (require-all {} (require-not {})))",
            subpath(&real_path(root))?,
            subpath(&home)?
        ));
    }
    let mut hidden = Vec::new();
    for file in &ctx.hidden_files {
        hidden.push(prefix_regex(&real_path(file))?);
    }
    for dir in &ctx.hidden_dirs {
        hidden.push(subpath(&real_path(dir))?);
    }
    line(format!(
        "(deny file-read* (with message \"{tag}\")\n  {})",
        hidden.join("\n  ")
    ));
    // Other sandboxes' folders, not the folder holding them: walking up from
    // the home (`mkdir -p`) must still see that it exists.
    let sandboxes = real_path(&ctx.sandboxes);
    line(format!(
        "(deny file-read* (with message \"{tag}\")\n  (require-all {} (require-not {}) (require-not {})))",
        subpath(&sandboxes)?,
        literal(&sandboxes)?,
        subpath(&real_path(&ctx.dir))?
    ));
    // The sandbox writes inside its home and each workspace, but may not
    // remove, rename or create the folder itself (a rename checks
    // `file-write-unlink` on the old path): each stays the folder this
    // policy was compiled for, and never becomes a link elsewhere.
    line(
        "\n;; ---- The home and each workspace themselves: never removed, renamed or replaced"
            .into(),
    );
    let mut roots = vec![literal(&home)?];
    for path in &writes {
        let root = literal(path)?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    line(format!(
        "(deny file-write-unlink file-write-create (with message \"{tag}\")\n  {})",
        roots.join("\n  ")
    ));
    Ok(Compiled {
        text: sb,
        extension: "sb",
    })
}

fn unsupported(reason: String) -> CompileError {
    CompileError::Unsupported {
        backend: BackendKind::Seatbelt,
        reason,
    }
}

/// A path as an SBPL string. Paths with a double quote or a backslash are
/// refused rather than escaped: a mistake there would change the rule.
fn quoted(path: &Path) -> Result<String, CompileError> {
    let text = path
        .to_str()
        .ok_or_else(|| unsupported(format!("{} is not valid UTF-8", path.display())))?;
    if text.contains('"') || text.contains('\\') {
        return Err(unsupported(format!(
            "the path {text} holds a quote or backslash"
        )));
    }
    Ok(format!("\"{text}\""))
}

fn subpath(path: &Path) -> Result<String, CompileError> {
    Ok(format!("(subpath {})", quoted(path)?))
}

fn literal(path: &Path) -> Result<String, CompileError> {
    Ok(format!("(literal {})", quoted(path)?))
}

/// Every path that starts with `path`, as a regex: `state.db` covers its
/// journal; `audit.jsonl` covers its moved-aside files.
fn prefix_regex(path: &Path) -> Result<String, CompileError> {
    quoted(path)?;
    let text = path.to_str().unwrap_or_default();
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if ".^$*+?()[]{}|".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    Ok(format!("(regex #\"^{escaped}\")"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;

    fn ctx(base: &Path) -> SandboxContext {
        let layout = Layout::at(base.join("alice/.enclos"));
        SandboxContext::new(&layout, &"home".parse().unwrap(), 41001)
    }

    fn policy() -> Policy {
        let mut p = Policy::default();
        p.fs.write = vec!["{home}".into(), "~/work".into()];
        p.fs.read_deny = vec!["~/.ssh".into(), "~/.netrc".into()];
        p
    }

    #[test]
    fn the_compiled_policy_has_every_section_in_order() {
        let base = Path::new("/nonexistent-enclos-test");
        let text = compile(&policy(), &ctx(base)).unwrap().text;
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("missing {needle}:\n{text}"))
        };
        assert!(at("(allow default)") < at("(deny file-write* (with message \"enclos:home\"))"));
        assert!(text.contains("(subpath \"/nonexistent-enclos-test/alice/work\")"));
        assert!(text.contains("(subpath \"/nonexistent-enclos-test/alice/.ssh\")"));
        assert_eq!(text.matches("(remote ip ").count(), 1);
        assert!(text.contains("(remote ip \"localhost:41001\")"));
        assert!(at("(deny network*") < at("(deny lsopen"));
        // The protected paths come after every allow, so nothing overrides them.
        let protected = at(";; ---- enclos's own files");
        assert!(text.rfind("(allow ").unwrap() < protected);
        for hidden in [
            "state\\.db",
            "state\\.lock",
            "audit\\.jsonl",
            "config\\.toml",
        ] {
            assert!(
                text[protected..].contains(&format!(
                    "(regex #\"^/nonexistent-enclos-test/alice/\\.enclos/{hidden}\")"
                )),
                "{hidden}: {text}"
            );
        }
        assert!(
            text[protected..].contains("(subpath \"/nonexistent-enclos-test/alice/.enclos/run\")")
        );
        assert!(text.contains(
            "(require-not (subpath \"/nonexistent-enclos-test/alice/.enclos/sandboxes/home\"))"
        ));
    }

    #[test]
    fn hidden_paths_come_after_every_grant_and_spare_the_home() {
        let base = Path::new("/nonexistent-enclos-test");
        let mut p = policy();
        p.fs.read_deny.push("{home}/private".into());
        p.fs.read_deny.push("~".into());
        let text = compile(&p, &ctx(base)).unwrap().text;
        let hidden = text
            .find("(deny file-read* file-write*")
            .unwrap_or_else(|| panic!("no hidden paths:\n{text}"));
        // Later rules win: no allow for files may follow the hidden paths.
        let last_allow = ["(allow file-write*", "(allow file-read*"]
            .iter()
            .filter_map(|a| text.rfind(a))
            .max()
            .unwrap();
        assert!(last_allow < hidden, "{text}");
        assert!(text[hidden..].contains(
            "(subpath \"/nonexistent-enclos-test/alice/.enclos/sandboxes/home/home/private\")"
        ));
        assert!(text[hidden..].contains(
            "(require-all (subpath \"/nonexistent-enclos-test/alice\") (require-not (subpath \"/nonexistent-enclos-test/alice/.enclos/sandboxes/home/home\")))"
        ), "{text}");
    }

    #[test]
    fn the_home_and_each_workspace_cannot_be_removed_renamed_or_created() {
        let base = Path::new("/nonexistent-enclos-test");
        let text = compile(&policy(), &ctx(base)).unwrap().text;
        let rule = text
            .find("(deny file-write-unlink file-write-create")
            .unwrap_or_else(|| panic!("no rule for the folders themselves:\n{text}"));
        // After every allow, so no grant reopens it.
        assert!(text.rfind("(allow ").unwrap() < rule, "{text}");
        let roots = &text[rule..];
        let roots = &roots[..roots.find("))").unwrap() + 1];
        let home = "(literal \"/nonexistent-enclos-test/alice/.enclos/sandboxes/home/home\")";
        assert!(roots.contains(home), "{text}");
        assert!(
            roots.contains("(literal \"/nonexistent-enclos-test/alice/work\")"),
            "{text}"
        );
        // `{home}` is in the policy too: listed once.
        assert_eq!(roots.matches(home).count(), 1, "{text}");

        // A policy that leaves `{home}` out still writes the home, so it
        // keeps the home in place too.
        let mut p = policy();
        p.fs.write = vec!["~/work".into()];
        let text = compile(&p, &ctx(base)).unwrap().text;
        let rule = text
            .find("(deny file-write-unlink file-write-create")
            .unwrap();
        let roots = &text[rule..];
        assert!(roots[..roots.find("))").unwrap()].contains(home), "{text}");
    }

    #[test]
    fn paths_that_would_change_a_rule_are_refused() {
        let mut p = policy();
        p.fs.write.push("/tmp/evil\") (allow default".into());
        let err = compile(&p, &ctx(Path::new("/x"))).unwrap_err();
        assert!(err.to_string().contains("quote"), "{err}");
    }
}
