//! Reading a sandbox home from the host (ADR 0023). The sandbox writes its
//! home, and a member may keep changing it while enclos reads, so every
//! folder is opened through its parent's descriptor without following a
//! link, and a file is opened the same way, checked with `fstat` and read
//! with a bound: a link, a FIFO or a growing file put in place before or
//! during the read leads nowhere.

use std::ffi::CStr;
use std::fmt;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::{NotRead, RuntimeAgentName, Unreadable};

/// A path relative to a sandbox home, made only of plain components: no
/// root, no `..`, no `.`, nothing empty. Adapters name every path they want
/// read this way, so none can lead out of the home.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HomePath(PathBuf);

impl HomePath {
    /// `None` unless every component is a plain name.
    pub fn new(path: impl Into<PathBuf>) -> Option<HomePath> {
        let path = path.into();
        let plain = path.components().next().is_some()
            && path.components().all(|c| matches!(c, Component::Normal(_)));
        plain.then_some(HomePath(path))
    }

    /// An agent's name is one plain component, so this cannot leave the home.
    pub fn join(&self, agent: &RuntimeAgentName) -> HomePath {
        HomePath(self.0.join(agent.as_str()))
    }

    /// A plain name below this path.
    pub fn child(&self, name: &str) -> Option<HomePath> {
        HomePath::new(self.0.join(name))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// As the sandbox sees it: `~/.hermes/auth.json`.
impl fmt::Display for HomePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "~/{}", self.0.display())
    }
}

pub(crate) fn unreadable(path: &str, why: NotRead) -> Unreadable {
    Unreadable {
        path: path.to_owned(),
        why,
    }
}

pub(crate) fn io(path: &str, e: Errno) -> Unreadable {
    unreadable(path, NotRead::Io(e.to_string()))
}

const FOLDER: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Opens the sandbox home itself. Its own path is enclos's, which the
/// sandbox cannot change; what is inside it is the sandbox's.
pub(crate) fn open_home(home: &Path) -> Result<OwnedFd, Unreadable> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    rustix::fs::open(home, flags, Mode::empty()).map_err(|e| match e {
        Errno::NOENT => unreadable("~", NotRead::Missing),
        Errno::NOTDIR => unreadable("~", NotRead::NotAFolder),
        e => io("~", e),
    })
}

/// Opens the folder `name` inside the open folder `dir`, through its
/// descriptor and without following a link in its place. `Ok(None)` when
/// there is no such entry; a link or a non-folder is `Unreadable`.
pub(crate) fn open_folder<P: rustix::path::Arg + Copy>(
    dir: impl AsFd,
    name: P,
    shown: &str,
) -> Result<Option<OwnedFd>, Unreadable> {
    match rustix::fs::openat(&dir, name, FOLDER, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        // A link is refused as a loop (Linux) or as not a folder (macOS).
        Err(Errno::LOOP | Errno::NOTDIR) => {
            let link = entry_stat(&dir, name, shown)?
                .is_some_and(|s| FileType::from_raw_mode(s.st_mode).is_symlink());
            Err(unreadable(
                shown,
                if link {
                    NotRead::Link
                } else {
                    NotRead::NotAFolder
                },
            ))
        }
        Err(e) => Err(io(shown, e)),
    }
}

/// What `name` is inside the open folder `dir`, without following a link
/// at its end: `None` when there is no such entry.
pub(crate) fn entry_stat<P: rustix::path::Arg>(
    dir: impl AsFd,
    name: P,
    shown: &str,
) -> Result<Option<Stat>, Unreadable> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(io(shown, e)),
    }
}

/// The folder holding `rel`'s last component, opened component by
/// component from the home, and that last name. `Ok(None)` when a folder on
/// the way does not exist.
fn parent_of(home: &Path, rel: &HomePath) -> Result<Option<(OwnedFd, String)>, Unreadable> {
    let mut names: Vec<&str> = Vec::new();
    for c in rel.as_path().components() {
        let Component::Normal(name) = c else {
            unreachable!("a home path has plain components only");
        };
        // A name that is not text cannot be one an adapter wrote.
        names.push(name.to_str().ok_or_else(|| {
            unreadable(
                &rel.to_string(),
                NotRead::Io("a name that is not text".into()),
            )
        })?);
    }
    let (last, folders) = names.split_last().expect("a home path is not empty");
    let mut dir = open_home(home)?;
    let mut shown = String::from("~");
    for name in folders {
        shown = format!("{shown}/{name}");
        match open_folder(&dir, *name, &shown)? {
            Some(next) => dir = next,
            None => return Ok(None),
        }
    }
    Ok(Some((dir, (*last).to_owned())))
}

/// What is at `rel`, without following a link anywhere on the way, the
/// last component included: `Ok(None)` when nothing is there, and a link at
/// the end is `Unreadable`, since what it points to is the sandbox's choice.
pub fn stat(home: &Path, rel: &HomePath) -> Result<Option<Stat>, Unreadable> {
    let shown = rel.to_string();
    let Some((dir, last)) = parent_of(home, rel)? else {
        return Ok(None);
    };
    match entry_stat(&dir, last.as_str(), &shown)? {
        Some(s) if FileType::from_raw_mode(s.st_mode).is_symlink() => {
            Err(unreadable(&shown, NotRead::Link))
        }
        found => Ok(found),
    }
}

/// The text of the plain file at `rel`, at most `max` bytes: `Ok(None)`
/// when nothing is there. The file is opened without following a link and
/// without waiting (a FIFO would block a plain open), checked to be a plain
/// file through its descriptor, and read no further than `max`, so a file
/// swapped or grown after a check cannot make the read larger.
pub fn read_text(home: &Path, rel: &HomePath, max: u64) -> Result<Option<String>, Unreadable> {
    let shown = rel.to_string();
    let Some((dir, last)) = parent_of(home, rel)? else {
        return Ok(None);
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(&dir, last.as_str(), flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(unreadable(&shown, NotRead::Link)),
        Err(e) => return Err(io(&shown, e)),
    };
    let meta = rustix::fs::fstat(&fd).map_err(|e| io(&shown, e))?;
    if !FileType::from_raw_mode(meta.st_mode).is_file() {
        return Err(unreadable(&shown, NotRead::NotAFile));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(&shown, NotRead::Io(e.to_string())))?;
    if bytes.len() as u64 > max {
        return Err(unreadable(&shown, NotRead::TooLarge(max)));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| unreadable(&shown, NotRead::NotText))
}

/// `x` as a wide integer: `stat` fields have different integer types on
/// each OS, and this takes any of them without a cast.
pub(crate) fn wide(x: impl Into<i128>) -> i128 {
    x.into()
}

/// A directory entry's name, as the walker reads it.
pub(crate) fn is_dot(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(p: &str) -> HomePath {
        HomePath::new(p).unwrap()
    }

    #[test]
    fn a_home_path_is_plain_and_relative() {
        for good in [".hermes/auth.json", "a", "a/b/c"] {
            assert_eq!(rel(good).as_path(), Path::new(good));
        }
        for bad in ["", "/", "/etc/passwd", "../x", "a/../b", "./a"] {
            assert!(HomePath::new(bad).is_none(), "{bad}");
        }
        assert_eq!(rel(".hermes/auth.json").to_string(), "~/.hermes/auth.json");
        let agent = RuntimeAgentName::new("my_bot").unwrap();
        assert_eq!(
            rel(".hermes/profiles").join(&agent).as_path(),
            Path::new(".hermes/profiles/my_bot")
        );
    }

    #[test]
    fn a_read_never_follows_a_link_and_refuses_what_is_not_a_small_plain_file() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "host").unwrap();
        std::fs::write(home.path().join("ok"), "hello").unwrap();
        assert_eq!(
            read_text(home.path(), &rel("ok"), 100),
            Ok(Some("hello".into()))
        );
        assert_eq!(read_text(home.path(), &rel("missing"), 100), Ok(None));
        assert_eq!(read_text(home.path(), &rel("no/such/file"), 100), Ok(None));

        // A link at the end, or on the way.
        std::os::unix::fs::symlink(outside.path().join("secret"), home.path().join("last"))
            .unwrap();
        assert_eq!(
            read_text(home.path(), &rel("last"), 100).unwrap_err(),
            unreadable("~/last", NotRead::Link)
        );
        std::os::unix::fs::symlink(outside.path(), home.path().join("way")).unwrap();
        assert_eq!(
            read_text(home.path(), &rel("way/secret"), 100).unwrap_err(),
            unreadable("~/way", NotRead::Link)
        );
        assert!(matches!(
            stat(home.path(), &rel("last")),
            Err(e) if e == unreadable("~/last", NotRead::Link)
        ));

        // Too large, not text, a folder, a FIFO (which must not block).
        std::fs::write(home.path().join("big"), vec![b'x'; 101]).unwrap();
        assert_eq!(
            read_text(home.path(), &rel("big"), 100).unwrap_err(),
            unreadable("~/big", NotRead::TooLarge(100))
        );
        std::fs::write(home.path().join("bin"), [0xff, 0xfe]).unwrap();
        assert_eq!(
            read_text(home.path(), &rel("bin"), 100).unwrap_err(),
            unreadable("~/bin", NotRead::NotText)
        );
        std::fs::create_dir(home.path().join("dir")).unwrap();
        assert_eq!(
            read_text(home.path(), &rel("dir"), 100).unwrap_err(),
            unreadable("~/dir", NotRead::NotAFile)
        );
        let fifo = home.path().join("fifo");
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            read_text(home.path(), &rel("fifo"), 100).unwrap_err(),
            unreadable("~/fifo", NotRead::NotAFile)
        );
    }
}
