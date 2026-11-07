//! The places a backend gives each session of its own, such as
//! bubblewrap's `/run` and `/proc`, and the workspaces that would put the
//! host's back over one (design §5).

use std::path::Path;

use super::paths::is_within;

/// A place each session has its own of, mounted before the workspaces: a
/// workspace's bind at it or at a folder holding it would put the host's
/// back over the sandbox's, and so would one that leads there through a
/// link, which the bind follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnPlace {
    pub path: &'static str,
    /// Whether a workspace may lie inside it, as `/tmp/proj` may: its bind
    /// brings back that one folder of the host's. Under `/run` or `/proc`,
    /// every folder is the host's own.
    pub holds_workspaces: bool,
}

/// A backend's own places; none where a session sees the host's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnPlaces(pub &'static [OwnPlace]);

impl OwnPlaces {
    pub const NONE: OwnPlaces = OwnPlaces(&[]);

    /// The own place a workspace at `path` would put the host's back over:
    /// the one `path` is at, or lies inside where no workspace may, else
    /// the first it holds. `path` is a workspace as written, or as it
    /// really is.
    pub fn undone_by(&self, path: &Path) -> Option<&'static str> {
        let at_or_inside = |own: &&OwnPlace| {
            let place = Path::new(own.path);
            is_within(path, place) && (path == place || !own.holds_workspaces)
        };
        let holds = |own: &&OwnPlace| is_within(Path::new(own.path), path);
        self.0
            .iter()
            .find(at_or_inside)
            .or_else(|| self.0.iter().find(holds))
            .map(|own| own.path)
    }
}

/// Links a user might make to a place, as the tests of what reads the host
/// make them.
#[cfg(test)]
pub(crate) mod links {
    use std::path::{Path, PathBuf};

    use crate::policy::paths::real_path;

    /// Places at or under bubblewrap's own, each with the one it lies in as
    /// this host resolves a link to it. macOS's `/tmp`, `/var/tmp` and
    /// `/var/run` lead into `/private`, so only Linux has them here.
    pub(crate) fn targets() -> Vec<(&'static str, &'static str)> {
        let mut targets = vec![
            ("/run", "/run"),
            ("/run/user/1000", "/run"),
            ("/dev", "/dev"),
            ("/dev/shm", "/dev/shm"),
            ("/proc", "/proc"),
            ("/proc/1", "/proc"),
        ];
        if cfg!(target_os = "linux") {
            targets.extend([
                ("/tmp", "/tmp"),
                ("/var/tmp", "/var/tmp"),
                ("/var/run", "/run"),
            ]);
        }
        targets
    }

    /// What a link in `folder` holds to reach `target` without a leading
    /// `/`: `../../run` from `/home/alice`.
    pub(crate) fn relative(folder: &Path, target: &str) -> PathBuf {
        let up = real_path(folder).components().count() - 1;
        PathBuf::from("../".repeat(up)).join(target.trim_start_matches('/'))
    }

    /// Two links in `folder` to `target`, `<name>-relative` and
    /// `<name>-absolute`.
    pub(crate) fn both(folder: &Path, name: &str, target: &str) -> [PathBuf; 2] {
        let relative = relative(folder, target);
        [("relative", relative), ("absolute", PathBuf::from(target))].map(|(kind, to)| {
            let at = folder.join(format!("{name}-{kind}"));
            std::os::unix::fs::symlink(to, &at).unwrap();
            at
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLACES: OwnPlaces = OwnPlaces(&[
        OwnPlace {
            path: "/tmp",
            holds_workspaces: true,
        },
        OwnPlace {
            path: "/run",
            holds_workspaces: false,
        },
    ]);

    #[test]
    fn a_workspace_at_or_holding_an_own_place_undoes_it() {
        for (path, place) in [("/tmp", "/tmp"), ("/run", "/run"), ("/", "/tmp")] {
            assert_eq!(PLACES.undone_by(Path::new(path)), Some(place), "{path}");
        }
    }

    #[test]
    fn a_workspace_inside_one_undoes_it_unless_it_holds_workspaces() {
        assert_eq!(PLACES.undone_by(Path::new("/run/user/1000")), Some("/run"));
        assert_eq!(PLACES.undone_by(Path::new("/tmp/proj")), None);
    }

    /// `/dev` is named for itself, not for the `/dev/shm` it holds.
    #[test]
    fn the_place_a_workspace_is_at_or_in_is_named_before_one_it_holds() {
        let nested = OwnPlaces(&[
            OwnPlace {
                path: "/dev/shm",
                holds_workspaces: false,
            },
            OwnPlace {
                path: "/dev",
                holds_workspaces: false,
            },
        ]);
        assert_eq!(nested.undone_by(Path::new("/dev")), Some("/dev"));
        assert_eq!(nested.undone_by(Path::new("/dev/shm/x")), Some("/dev/shm"));
        assert_eq!(nested.undone_by(Path::new("/")), Some("/dev/shm"));
    }

    #[test]
    fn a_workspace_beside_them_undoes_nothing() {
        for path in ["/home/alice/proj", "/runner", "/tmpfiles", "/var/tmp"] {
            assert_eq!(PLACES.undone_by(Path::new(path)), None, "{path}");
        }
        assert_eq!(OwnPlaces::NONE.undone_by(Path::new("/run")), None);
    }
}
