//! Paths in policies: expanding `~`, `{home}` and `{tmp}`, and resolving
//! symlinks and `..` so that checks see the real location (design §5).

use std::path::{Component, Path, PathBuf};

use crate::model::policy::FsPolicy;

/// What policy paths expand against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContext {
    /// The user's own home folder, for `~`.
    pub user_home: PathBuf,
    /// The sandbox's home folder, for `{home}`.
    pub sandbox_home: PathBuf,
}

impl PathContext {
    /// The sandbox's temporary folder, inside its home (ADR 0015).
    pub fn sandbox_tmp(&self) -> PathBuf {
        self.sandbox_home.join("tmp")
    }

    /// Expands one policy path to an absolute path, or says why it cannot.
    pub fn expand(&self, entry: &str) -> Result<PathBuf, String> {
        let under = |base: &Path, rest: &str| -> Result<PathBuf, String> {
            match rest {
                "" => Ok(base.to_owned()),
                rest => rest
                    .strip_prefix('/')
                    .map(|rest| base.join(rest))
                    .ok_or_else(|| format!("`{entry}`: put a / after the placeholder")),
            }
        };
        if let Some(rest) = entry.strip_prefix("{home}") {
            return under(&self.sandbox_home, rest);
        }
        if let Some(rest) = entry.strip_prefix("{tmp}") {
            return under(&self.sandbox_tmp(), rest);
        }
        if let Some(rest) = entry.strip_prefix('~') {
            return under(&self.user_home, rest);
        }
        if Path::new(entry).is_absolute() {
            return Ok(PathBuf::from(entry));
        }
        Err(format!(
            "`{entry}` is not an absolute path: start it with /, ~, {{home}} or {{tmp}}"
        ))
    }
}

/// How many symlinks `real_path` follows by hand before it stops, as the
/// kernel does for a loop.
const MAX_LINKS: usize = 40;

/// Where `path` really is: each existing component's symlinks resolved, and
/// `..` taken after resolving what it climbs out of. A symlink to something
/// that does not exist yet is followed to where it points. The part that does
/// not exist yet is kept as written, without `.` and with its `..` applied.
pub fn real_path(path: &Path) -> PathBuf {
    follow(path, 0)
}

fn follow(path: &Path, links: usize) -> PathBuf {
    let mut real = PathBuf::new();
    let mut components = path.components();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => real = PathBuf::from("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                real.pop();
            }
            Component::Normal(name) => {
                real.push(name);
                let Ok(meta) = real.symlink_metadata() else {
                    continue;
                };
                if let Ok(resolved) = real.canonicalize() {
                    real = resolved;
                } else if meta.is_symlink()
                    && links < MAX_LINKS
                    && let Ok(target) = std::fs::read_link(&real)
                {
                    // A dangling link: what it points to, relative to its
                    // folder, then the rest of the path.
                    real.pop();
                    let next = real.join(target).join(components.as_path());
                    return follow(&next, links + 1);
                }
            }
        }
    }
    real
}

/// Every symlink followed on the way to `path`, in the order `real_path`
/// follows them, including links a link points through. Each is given as
/// the link itself: its folder resolved, its own name kept.
pub fn links_on_the_way(path: &Path) -> Vec<PathBuf> {
    let mut links = Vec::new();
    walk(path, &mut links);
    links
}

fn walk(path: &Path, links: &mut Vec<PathBuf>) {
    let mut real = PathBuf::new();
    let mut components = path.components();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => real = PathBuf::from("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                real.pop();
            }
            Component::Normal(name) => {
                real.push(name);
                let is_link = real.symlink_metadata().is_ok_and(|m| m.is_symlink());
                if !is_link || links.len() >= MAX_LINKS {
                    continue;
                }
                let Ok(target) = std::fs::read_link(&real) else {
                    continue;
                };
                links.push(real.clone());
                real.pop();
                let next = real.join(target).join(components.as_path());
                return walk(&next, links);
            }
        }
    }
}

/// Whether `inner` is `outer` or inside it, comparing whole components.
pub fn is_within(inner: &Path, outer: &Path) -> bool {
    inner.starts_with(outer)
}

/// A policy's filesystem paths, expanded and real, as the sandbox sees
/// them. The compiler and `policy test` both start from this, so the probes
/// check the folders the compiled rules name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsPaths {
    /// The sandbox home, always writable.
    pub home: PathBuf,
    /// The policy's write grants.
    pub writes: Vec<PathBuf>,
    /// The policy's read deny list.
    pub read_deny: Vec<PathBuf>,
}

impl FsPaths {
    /// Expands and resolves every entry; one that does not expand is an
    /// error, never a path silently left out.
    pub fn of(fs: &FsPolicy, ctx: &PathContext) -> Result<FsPaths, String> {
        let expand = |entries: &[String]| -> Result<Vec<PathBuf>, String> {
            entries
                .iter()
                .map(|e| ctx.expand(e).map(|p| real_path(&p)))
                .collect()
        };
        Ok(FsPaths {
            home: real_path(&ctx.sandbox_home),
            writes: expand(&fs.write)?,
            read_deny: expand(&fs.read_deny)?,
        })
    }

    /// The folders the sandbox may write in but must not move (design §5):
    /// the sandbox home, every workspace, and every folder inside them that
    /// holds a deny-list entry. Moving one of them would carry what it holds
    /// to a path no deny rule names. Sorted, without repeats.
    pub fn unmovable(&self) -> Vec<PathBuf> {
        let writable: Vec<&Path> = std::iter::once(self.home.as_path())
            .chain(self.writes.iter().map(PathBuf::as_path))
            .collect();
        let inside_writable = |p: &Path| writable.iter().any(|w| is_within(p, w));
        let holding_denied = self
            .read_deny
            .iter()
            .flat_map(|entry| entry.ancestors().skip(1))
            .filter(|a| inside_writable(a));
        let mut folders: Vec<PathBuf> = writable
            .iter()
            .copied()
            .chain(holding_denied)
            .map(Path::to_path_buf)
            .collect();
        folders.sort();
        folders.dedup();
        folders
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PathContext {
        PathContext {
            user_home: "/Users/alice".into(),
            sandbox_home: "/Users/alice/.enclos/sandboxes/home/home".into(),
        }
    }

    #[test]
    fn placeholders_and_tilde_expand() {
        let ctx = ctx();
        assert_eq!(ctx.expand("~").unwrap(), PathBuf::from("/Users/alice"));
        assert_eq!(
            ctx.expand("~/notes").unwrap(),
            PathBuf::from("/Users/alice/notes")
        );
        assert_eq!(ctx.expand("{home}").unwrap(), ctx.sandbox_home);
        assert_eq!(
            ctx.expand("{tmp}/x").unwrap(),
            ctx.sandbox_home.join("tmp/x")
        );
        assert_eq!(ctx.expand("/opt/x").unwrap(), PathBuf::from("/opt/x"));
        assert!(ctx.expand("notes").is_err());
        assert!(ctx.expand("~alice").is_err());
    }

    #[test]
    fn real_path_resolves_symlinks_and_dot_dot() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("protected/inner")).unwrap();
        std::fs::create_dir(base.join("work")).unwrap();
        std::os::unix::fs::symlink(base.join("protected"), base.join("work/link")).unwrap();

        // Through the symlink, into a part that does not exist yet.
        assert_eq!(
            real_path(&base.join("work/link/inner/new")),
            base.join("protected/inner/new")
        );
        // `..` after a symlink climbs out of where it points, not where it sits.
        assert_eq!(real_path(&base.join("work/link/../x")), base.join("x"));
        assert_eq!(real_path(&base.join("work/./a/../b")), base.join("work/b"));
    }

    #[test]
    fn real_path_follows_a_link_to_what_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("protected")).unwrap();
        std::fs::create_dir(base.join("work")).unwrap();
        let link = |target: &str, at: &str| {
            std::os::unix::fs::symlink(target, base.join(at)).unwrap();
        };
        link(
            base.join("protected/later").to_str().unwrap(),
            "work/absolute",
        );
        link("../protected/later", "work/relative");
        link("relative", "work/chained");

        for at in ["work/absolute", "work/relative", "work/chained"] {
            assert_eq!(
                real_path(&base.join(at)),
                base.join("protected/later"),
                "{at}"
            );
            assert_eq!(
                real_path(&base.join(at).join("x")),
                base.join("protected/later/x"),
                "{at}"
            );
        }
        // A loop ends instead of following forever.
        link("loop-b", "work/loop-a");
        link("loop-a", "work/loop-b");
        real_path(&base.join("work/loop-a/x"));
    }

    #[test]
    fn every_link_on_the_way_is_found_where_it_sits() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("a/real")).unwrap();
        std::fs::create_dir(base.join("b")).unwrap();
        let link = |target: &str, at: &str| {
            std::os::unix::fs::symlink(target, base.join(at)).unwrap();
        };
        // `top` -> `b/hop` -> `a/real`, and a dangling one past it.
        link("../a/real", "b/hop");
        link("b/hop", "top");
        link("../not-yet", "a/real/gone");
        assert_eq!(
            links_on_the_way(&base.join("top/gone/x")),
            vec![
                base.join("top"),
                base.join("b/hop"),
                base.join("a/real/gone")
            ]
        );
        assert!(links_on_the_way(&base.join("a/real/new")).is_empty());
        // A loop ends.
        link("loop-b", "b/loop-a");
        link("loop-a", "b/loop-b");
        assert!(links_on_the_way(&base.join("b/loop-a")).len() <= MAX_LINKS);
    }

    #[test]
    fn the_writable_folders_and_those_holding_a_denied_path_inside_them_cannot_move() {
        let u = "/nonexistent-enclos-test/u";
        let ctx = PathContext {
            user_home: u.into(),
            sandbox_home: format!("{u}/.enclos/sandboxes/s/home").into(),
        };
        let s = |v: &[&str]| v.iter().map(|e| e.to_string()).collect::<Vec<_>>();
        let fs = FsPolicy {
            // The home again, a workspace twice, and one holding nothing denied.
            write: s(&["{home}", "~/work", "~/work/", "~/plain"]),
            read_deny: s(&[
                "~/.ssh",
                "~/work/a/b/private",
                "~/work/a/key",
                "{home}/c/private",
                "~",
            ]),
        };
        let paths = FsPaths::of(&fs, &ctx).unwrap();
        assert_eq!(paths.home, ctx.sandbox_home);
        let p = |s: &str| PathBuf::from(format!("{u}{s}"));
        assert_eq!(
            paths.unmovable(),
            [
                p("/.enclos/sandboxes/s/home"),
                p("/.enclos/sandboxes/s/home/c"),
                p("/plain"),
                p("/work"),
                p("/work/a"),
                p("/work/a/b"),
            ]
        );
        // An entry that does not expand is an error, not a folder left out.
        let bad = FsPolicy {
            write: s(&["work"]),
            read_deny: Vec::new(),
        };
        assert!(FsPaths::of(&bad, &ctx).unwrap_err().contains("`work`"));
    }

    #[test]
    fn within_compares_whole_components() {
        assert!(is_within(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(is_within(Path::new("/a/b"), Path::new("/a/b")));
        assert!(!is_within(Path::new("/a/bc"), Path::new("/a/b")));
    }
}
