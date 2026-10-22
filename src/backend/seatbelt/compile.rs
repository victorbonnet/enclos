//! Compiling a policy for Seatbelt (design §5): `(allow default)`,
//! then writes only where granted, no terminal device but the session's own
//! and those the sandbox opens, reads of the sandbox home, the sensitive
//! deny list for reads and writes (after those allows, so no grant covers
//! it), the writable folders that cannot move (so no rename or clone carries
//! a denied path elsewhere), network only over TCP to the sandbox's proxy
//! port on loopback and to Unix sockets in its home, the host-service
//! denials, and last, so no rule above can override them, enclos's protected
//! paths and the home and workspaces themselves, which stay where they are.
//!
//! Seatbelt matches real paths, so every path is resolved first (`/tmp` is
//! `/private/tmp` on macOS). Every denial carries the sandbox's tag, which
//! the unified log repeats, to tell sandboxes apart.

use std::path::Path;

use super::super::{CompileError, Compiled, SandboxContext};
use crate::model::policy::Policy;
use crate::model::sandbox::{BackendKind, PORT_FIRST, PORT_LAST};
use crate::policy::paths::{FsPaths, PathContext, is_within, real_path};

const HOST_SERVICES: &str = include_str!("host-services.sb");

/// Device files every runtime writes to (shown by the prototype: shells,
/// Python, Node and Hermes). `/dev/tty` is the terminal a session runs in,
/// whatever its name; terminal devices by name are in [`TERMINALS`].
const DEVICES: &[&str] = &[
    "(literal \"/dev/null\")",
    "(literal \"/dev/zero\")",
    "(literal \"/dev/random\")",
    "(literal \"/dev/urandom\")",
    "(literal \"/dev/tty\")",
    "(literal \"/dev/ptmx\")",
    "(literal \"/dev/dtracehelper\")",
    "(regex #\"^/dev/fd/[0-9]+$\")",
];

/// Every terminal device: one per terminal tab or window, the user's other
/// sessions included. `wrap` checks a name it passes against the same form.
const TERMINALS: &str = "(regex #\"^/dev/ttys[0-9]+$\")";

/// The `sandbox-exec` parameter that names the terminal a session runs in,
/// set by `wrap`. Unset, as for a service, no terminal opens by name but
/// those the sandbox opens itself.
pub const TERMINAL_PARAM: &str = "ENCLOS_TERMINAL";

/// The `sandbox-exec` parameter that names, as `localhost:<port>`, the
/// port where the sandbox's runtime service listens, set by `wrap` for a
/// session started while it listens (ADR 0028). Unset (for the service
/// itself, a probe, or a session started while the service does not
/// listen), the program reaches its proxy alone.
pub const SERVICE_PARAM: &str = "ENCLOS_SERVICE";

/// What macOS grants a process for a pseudo-terminal it opens through
/// `/dev/ptmx`, which Apple's own `application.sb` allows the same way.
const PTY_EXTENSION: &str = "com.apple.sandbox.pty";

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
    let fs = FsPaths::of(&policy.fs, &paths).map_err(unsupported)?;
    let FsPaths {
        home,
        writes,
        read_deny,
    } = &fs;

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
    let mut allowed = vec![subpath(home)?];
    for path in writes {
        allowed.push(subpath(path)?);
    }
    allowed.extend(DEVICES.iter().map(|d| d.to_string()));
    line(format!("(allow file-write*\n  {})", allowed.join("\n  ")));

    line("\n;; ---- Terminals: the session's own and those the sandbox opens, no other".into());
    line(format!(
        "(deny file-read* file-write* (with message \"{tag}\") {TERMINALS})"
    ));
    // Under `(allow default)` a sandbox may issue extensions (Apple's
    // `application.sb` starts from `(deny default)`, which refuses them):
    // without this rule it could grant itself this one for another terminal.
    // A backend test shows both.
    line(format!(
        "(deny file-issue-extension (with message \"{tag}\") (extension-class \"{PTY_EXTENSION}\"))"
    ));
    line(format!(
        "(allow file-read* file-write* (require-all {TERMINALS} (extension \"{PTY_EXTENSION}\")))"
    ));
    line(format!(
        "(if (param \"{TERMINAL_PARAM}\")\n  (allow file-read* file-write* (require-all {TERMINALS} (literal (param \"{TERMINAL_PARAM}\")))))"
    ));

    line(format!("(allow file-read* {})", subpath(home)?));

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
                if is_within(home, p) {
                    Ok(format!(
                        "(require-all {} (require-not {}))",
                        subpath(p)?,
                        subpath(home)?
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
        "\n;; ---- Writable folders that cannot move, so no rename or clone carries a denied path elsewhere"
            .into(),
    );
    line(unmovable_rule(&fs, &tag)?);

    // A sandbox that listens binds no port of the proxy range (below): one
    // whose proxy port is elsewhere could have it taken by another sandbox.
    if !(PORT_FIRST..=PORT_LAST).contains(&ctx.proxy_port) {
        return Err(CompileError::Unsupported {
            backend: BackendKind::Seatbelt,
            reason: format!(
                "sandbox {name} has proxy port {port}, outside enclos's proxy range {PORT_FIRST} to {PORT_LAST}, which sandboxes that listen are kept from binding (ADR 0028); make it again with `enclos sandbox rm {name}`, then `enclos sandbox create {name}`",
                name = ctx.name,
                port = ctx.proxy_port,
            ),
        });
    }
    line(
        "\n;; ---- Network: only the sandbox's proxy, and Unix sockets in its home (ADR 0007)"
            .into(),
    );
    line(format!("(deny network* (with message \"{tag}\"))"));
    // `tcp`: TCP only, since the proxy holds no UDP socket at the port
    // (`ip` let UDP through too on macOS 26.5.2). On that version `tcp`
    // opens the port on `[::1]` as well as 127.0.0.1, so the proxy listens
    // on both (`proxy::listen`). `tcp4` or `ip4` would leave only 127.0.0.1
    // open on macOS 26.5.2, but on CI's macOS 14 runner `ip4` did not let
    // the sandbox reach 127.0.0.1 at all.
    line(format!(
        "(allow network-outbound (remote tcp \"localhost:{}\"))",
        ctx.proxy_port
    ));
    line(format!(
        "(allow network-bind network-inbound (local unix-socket {}))",
        subpath(home)?
    ));
    line(format!(
        "(allow network-outbound (remote unix-socket {}))",
        subpath(home)?
    ));
    if policy.net.listen {
        // A runtime's own listener (ADR 0028). Seatbelt refuses `localhost:0`
        // and `localhost` does not hold a bind to loopback (a bind on 0.0.0.0
        // passes too, macOS 26.5.2), so this opens every port on every
        // address. Then each port of the proxy range is closed again, every
        // install's, reserved before this policy was compiled or after, so
        // no sandbox takes another's proxy port while that proxy is not
        // running: an exact-port deny after the allow holds on 127.0.0.1,
        // 0.0.0.0, [::1] and [::] (backend tests), and Seatbelt refuses
        // before the port is found in use. It has no port ranges, hence one
        // rule a port.
        line("(allow network-bind network-inbound (local tcp \"localhost:*\"))".into());
        for port in PORT_FIRST..=PORT_LAST {
            line(format!(
                "(deny network-bind (local tcp \"*:{port}\") (with message \"{tag}\"))"
            ));
        }
        // And a session started while the runtime's service listens reaches
        // that one port, which `wrap` names: the port it held when the
        // session started, so every agent's client finds it and gets its own
        // ticket, as outside enclos. `tcp4` opens it on 127.0.0.1 alone,
        // where the service listens, not on [::1], which any other program, on
        // the host or in another sandbox, could hold at that port (`tcp` opens
        // both, checked by hand on macOS 26.5.2).
        // A parameter, so every session runs under this one compiled policy.
        line(format!(
            "(if (param \"{SERVICE_PARAM}\")\n  (allow network-outbound (remote tcp4 (param \"{SERVICE_PARAM}\"))))"
        ));
    }

    line(String::new());
    line(HOST_SERVICES.replace("{tag}", &tag).trim_end().to_owned());

    line("\n;; ---- enclos's own files, whatever the policy says (ADR 0010)".into());
    for root in &ctx.protected {
        line(format!(
            "(deny file-write* (with message \"{tag}\")\n  (require-all {} (require-not {})))",
            subpath(&real_path(root))?,
            subpath(home)?
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
    let mut roots = vec![literal(home)?];
    for path in writes {
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

/// The writable folders that must not move (design §5): deny rules match
/// paths, so a folder holding a denied path, renamed, would carry it to a
/// path no rule names, and a workspace could be moved into the home. A
/// rename needs `file-write-unlink` on its source, and on its destination
/// when that exists, and so does a removal, so denying it on these folders
/// alone stops them moving while the other files and folders inside them
/// are still made, renamed and removed. `file-clone` is denied on them too:
/// cloning a folder copies everything under it in one call, so it would
/// copy denied paths with it.
fn unmovable_rule(fs: &FsPaths, tag: &str) -> Result<String, CompileError> {
    let folders = fs
        .unmovable()
        .iter()
        .map(|f| literal(f))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "(deny file-write-unlink file-clone (with message \"{tag}\")\n  {})",
        folders.join("\n  ")
    ))
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
    fn a_proxy_port_outside_the_range_is_refused() {
        let layout = Layout::at(Path::new("/nonexistent-enclos-test/alice/.enclos"));
        let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 45000);
        let err = compile(&policy(), &ctx).unwrap_err().to_string();
        assert!(err.contains("proxy port 45000, outside"), "{err}");
        assert!(err.contains("enclos sandbox rm home"), "{err}");
    }

    #[test]
    fn a_policy_that_does_not_listen_binds_only_unix_sockets_in_the_home() {
        let base = Path::new("/nonexistent-enclos-test");
        let text = compile(&policy(), &ctx(base)).unwrap().text;
        assert_eq!(text.matches("(local tcp").count(), 0, "{text}");
        assert_eq!(text.matches("(allow network-bind").count(), 1, "{text}");
        assert!(text.contains("(allow network-bind network-inbound (local unix-socket"));
        // Nor reaches a service of its runtime: it has none that listens.
        assert!(!text.contains("ENCLOS_SERVICE"), "{text}");
    }

    #[test]
    fn a_policy_that_listens_lets_a_session_reach_the_service_port_it_is_given() {
        let base = Path::new("/nonexistent-enclos-test");
        let mut p = policy();
        p.net.listen = true;
        let text = compile(&p, &ctx(base)).unwrap().text;
        // A parameter, so every session runs under the same file.
        assert!(text.contains(
            "(if (param \"ENCLOS_SERVICE\")\n  (allow network-outbound (remote tcp4 (param \"ENCLOS_SERVICE\"))))"
        ));
        assert!(!text.contains("61374"));
    }

    #[test]
    fn a_policy_that_listens_binds_tcp_but_no_proxy_port_of_any_install() {
        let base = Path::new("/nonexistent-enclos-test");
        let mut p = policy();
        p.net.listen = true;
        let text = compile(&p, &ctx(base)).unwrap().text;
        let at = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("missing {needle}:\n{text}"))
        };
        let allow = at("(allow network-bind network-inbound (local tcp \"localhost:*\"))");
        // Later rules win: each deny comes after the allow, on every address,
        // for the whole range, not only the ports reserved now.
        assert_eq!(text.matches("(deny network-bind (local tcp").count(), 1000);
        for port in [PORT_FIRST, 41001, 41500, PORT_LAST] {
            let deny = at(&format!(
                "(deny network-bind (local tcp \"*:{port}\") (with message \"enclos:home\"))"
            ));
            assert!(allow < deny, "{port}");
        }
        // Outbound: the proxy port, and the service port a session is given.
        assert_eq!(text.matches("(remote tcp").count(), 2);
        assert!(text.contains("(remote tcp \"localhost:41001\")"));
        assert!(text.contains("(remote tcp4 (param \"ENCLOS_SERVICE\"))"));
        assert!(at("(deny network*") < allow);
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
        // One rule, `tcp`: not `ip`, which lets UDP through, nor `ip4`,
        // which did not reach 127.0.0.1 on macOS 14. The proxy holds the
        // port on both loopbacks.
        assert_eq!(text.matches("(remote ip").count(), 0);
        assert_eq!(text.matches("(remote tcp").count(), 1);
        assert!(text.contains("(allow network-outbound (remote tcp \"localhost:41001\"))"));
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
        let sensitive = text
            .find(";; ---- Sensitive paths")
            .unwrap_or_else(|| panic!("no sensitive paths:\n{text}"));
        let hidden = text[sensitive..]
            .find("(deny file-read* file-write*")
            .map(|at| sensitive + at)
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
    fn writable_folders_holding_a_hidden_path_cannot_move() {
        let base = Path::new("/nonexistent-enclos-test");
        let mut p = policy();
        p.fs.read_deny.push("~/work/project/private".into());
        p.fs.read_deny.push("{home}/a/private".into());
        let text = compile(&p, &ctx(base)).unwrap().text;
        let rule = text
            .find("(deny file-write-unlink")
            .unwrap_or_else(|| panic!("no unmovable folders:\n{text}"));
        let home = "/nonexistent-enclos-test/alice/.enclos/sandboxes/home/home";
        let folders: Vec<&str> = text[rule..]
            .lines()
            .skip(1)
            .take_while(|l| l.starts_with("  (literal "))
            .filter_map(|l| l.split('"').nth(1))
            .collect();
        assert_eq!(
            folders,
            [
                home.to_owned(),
                format!("{home}/a"),
                "/nonexistent-enclos-test/alice/work".to_owned(),
                "/nonexistent-enclos-test/alice/work/project".to_owned(),
            ],
            "{text}"
        );
        assert!(
            text[rule..]
                .starts_with("(deny file-write-unlink file-clone (with message \"enclos:home\")")
        );
        // A deny rule: after every allow for files, before the protected paths.
        let last_allow = ["(allow file-write*", "(allow file-read*"]
            .iter()
            .filter_map(|a| text.rfind(a))
            .max()
            .unwrap();
        assert!(last_allow < rule, "{text}");
        assert!(
            rule < text.find(";; ---- enclos's own files").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn terminal_devices_are_open_only_for_the_session_and_ptys_the_sandbox_makes() {
        let text = compile(&policy(), &ctx(Path::new("/x"))).unwrap().text;
        // No rule allows every terminal device: each allow narrows it.
        let ttys = "(regex #\"^/dev/ttys[0-9]+$\")";
        let allowed = text
            .lines()
            .filter(|l| l.contains(ttys) && l.contains("(allow "))
            .collect::<Vec<_>>();
        assert_eq!(allowed.len(), 2, "{text}");
        assert!(
            allowed
                .iter()
                .all(|l| l.contains(&format!("(require-all {ttys} "))),
            "{text}"
        );
        assert!(!text.contains(&format!("\n  {ttys}")), "{text}");
        let terminals = text
            .find(";; ---- Terminals")
            .unwrap_or_else(|| panic!("no terminals section:\n{text}"));
        let deny = text
            .find(&format!(
                "(deny file-read* file-write* (with message \"enclos:home\") {ttys})"
            ))
            .unwrap_or_else(|| panic!("no terminal deny:\n{text}"));
        assert!(deny > terminals, "{text}");
        assert!(text.contains(
            "(deny file-issue-extension (with message \"enclos:home\") (extension-class \"com.apple.sandbox.pty\"))"
        ), "{text}");
        assert!(
            text.contains(&format!(
                "(require-all {ttys} (extension \"com.apple.sandbox.pty\"))"
            )),
            "{text}"
        );
        assert!(text.contains(&format!(
            "(if (param \"ENCLOS_TERMINAL\")\n  (allow file-read* file-write* (require-all {ttys} (literal (param \"ENCLOS_TERMINAL\")))))"
        )), "{text}");
        // The allows come after the deny, so they win for what they match.
        let first_allow = text.find(&format!("(require-all {ttys} ")).unwrap();
        assert!(first_allow > deny, "{text}");
    }

    #[test]
    fn paths_that_would_change_a_rule_are_refused() {
        let mut p = policy();
        p.fs.write.push("/tmp/evil\") (allow default".into());
        let err = compile(&p, &ctx(Path::new("/x"))).unwrap_err();
        assert!(err.to_string().contains("quote"), "{err}");
    }
}
