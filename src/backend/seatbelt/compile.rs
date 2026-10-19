//! Compiling a policy for Seatbelt (design §5): `(allow default)`,
//! then writes only where granted, the sensitive read deny list, network only
//! to the sandbox's proxy port, the host-service denials, and last, so no
//! rule above can override them, enclos's protected paths.
//!
//! Seatbelt matches real paths, so every path is resolved first (`/tmp` is
//! `/private/tmp` on macOS). Every denial carries the sandbox's tag, which
//! the unified log repeats, to tell sandboxes apart.

use std::path::{Path, PathBuf};

use super::super::{CompileError, Compiled, SandboxContext};
use crate::model::policy::Policy;
use crate::model::sandbox::BackendKind;
use crate::policy::paths::{PathContext, real_path};

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

    line("\n;; ---- Reads: everything but the sensitive paths (ADR 0015)".into());
    if !read_deny.is_empty() {
        let denied = read_deny
            .iter()
            .map(|p| subpath(p))
            .collect::<Result<Vec<_>, _>>()?;
        line(format!(
            "(deny file-read* (with message \"{tag}\")\n  {})",
            denied.join("\n  ")
        ));
    }
    line(format!("(allow file-read* {})", subpath(&home)?));

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
    let data = real_path(&ctx.data);
    line(format!(
        "(deny file-read* (with message \"{tag}\")\n  {}\n  {}\n  {}\n  {})",
        prefix_regex(&data.join("state."))?,
        prefix_regex(&data.join("audit.jsonl"))?,
        literal(&real_path(&ctx.config_file))?,
        subpath(&data.join("run"))?,
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

/// Every path that starts with `path`, as a regex: `state.` covers state.db,
/// its journal and the lock; `audit.jsonl` covers its moved-aside files.
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

    fn ctx(base: &Path) -> SandboxContext {
        let data = base.join("alice/.enclos");
        SandboxContext {
            name: "home".parse().unwrap(),
            dir: data.join("sandboxes/home"),
            home: data.join("sandboxes/home/home"),
            user_home: base.join("alice"),
            protected: vec![data.clone()],
            sandboxes: data.join("sandboxes"),
            data: data.clone(),
            config_file: data.join("config.toml"),
            proxy_port: 41001,
        }
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
        assert!(
            text.contains("(regex #\"^/nonexistent-enclos-test/alice/\\.enclos/state\\.\")"),
            "{text}"
        );
        assert!(text.contains(
            "(require-not (subpath \"/nonexistent-enclos-test/alice/.enclos/sandboxes/home\"))"
        ));
    }

    #[test]
    fn paths_that_would_change_a_rule_are_refused() {
        let mut p = policy();
        p.fs.write.push("/tmp/evil\") (allow default".into());
        let err = compile(&p, &ctx(Path::new("/x"))).unwrap_err();
        assert!(err.to_string().contains("quote"), "{err}");
    }
}
