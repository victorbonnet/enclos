//! A runtime's latest release, looked up on the host (ADR 0074, proposed):
//! the release its installer installs by default, and whether this enclos
//! was checked with it. The answer is kept in `runtime-releases.json`: six
//! hours for a release, half an hour after a failed lookup, so `status`
//! reaches the network at most that often for each runtime while the file
//! can be written. A host turns lookups off with `runtime_releases = false`
//! in `config.toml`; a value enclos cannot read there turns them off too,
//! and `status` says why.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Engine;
use super::staging::{DownloadFailed, LOOKUP_MAX_BYTES};
use super::status::Fact;
use crate::config;
use crate::layout::{LayoutError, RUNTIME_RELEASES_FILE as KEPT};
use crate::model::Timestamp;
use crate::model::runtime::{RuntimeKind, RuntimeVersion};
use crate::runtime::RuntimeAdapter;

/// How long a release looked up is kept, in seconds.
const KEEP_FOUND: i64 = 6 * 3600;
/// How long a failed lookup is kept, so an offline host does not wait for
/// the network at each `status`.
const KEEP_FAILED: i64 = 30 * 60;

/// A runtime's latest release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LatestRelease {
    pub version: String,
    /// Whether this enclos release was checked with it: enclos's runtime
    /// tests passed with it before this release.
    pub checked: bool,
}

/// What a lookup found, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Lookup {
    /// When, in seconds since the epoch.
    at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failed: Option<String>,
}

impl Lookup {
    fn fresh(&self, now: i64) -> bool {
        let keep = match self.version {
            Some(_) => KEEP_FOUND,
            None => KEEP_FAILED,
        };
        // A time ahead of now, from a clock set back, is not trusted.
        (0..keep).contains(&(now - self.at))
    }
}

/// The latest releases found for one answer, by runtime: each runtime is
/// asked for once for all its sandboxes, even when nothing can be kept.
pub struct Releases {
    found: RefCell<HashMap<RuntimeKind, Fact<LatestRelease>>>,
    look_up: bool,
    due: Cell<bool>,
}

impl Default for Releases {
    /// [`Releases::looking_up`].
    fn default() -> Releases {
        Releases::looking_up()
    }
}

impl Releases {
    /// Each runtime's latest release, looked up when what is kept is too
    /// old: `status`'s, which may wait on the network.
    pub fn looking_up() -> Releases {
        Releases {
            found: RefCell::default(),
            look_up: true,
            due: Cell::new(false),
        }
    }

    /// Only what is kept, however old, so the answer comes at once, for a
    /// caller that must not wait on the network, such as the bridge:
    /// [`Releases::due`] then says whether a lookup is due.
    pub fn kept() -> Releases {
        Releases {
            look_up: false,
            ..Releases::looking_up()
        }
    }

    /// Whether a runtime asked for had nothing kept, or what was kept is
    /// older than its keep time, and was not looked up.
    pub fn due(&self) -> bool {
        self.due.get()
    }

    pub(super) fn of(
        &self,
        engine: &Engine,
        runtime: &dyn RuntimeAdapter,
        now: Timestamp,
    ) -> Fact<LatestRelease> {
        if let Some(found) = self.found.borrow().get(&runtime.kind()) {
            return found.clone();
        }
        let (found, due) = engine.release(runtime, now, self.look_up);
        self.due.set(self.due.get() || due);
        self.found
            .borrow_mut()
            .insert(runtime.kind(), found.clone());
        found
    }
}

impl Engine {
    /// The latest release of `runtime`, as kept or looked up now. Not
    /// provided when the runtime names no release or the host turned
    /// lookups off; "cannot tell" when the lookup failed, or when
    /// `config.toml` cannot say whether lookups are on, never "up to date".
    pub(super) fn latest_release(
        &self,
        runtime: &dyn RuntimeAdapter,
        now: Timestamp,
    ) -> Fact<LatestRelease> {
        self.release(runtime, now, true).0
    }

    /// [`Engine::latest_release`], looking nothing up unless `look_up`:
    /// then what is kept, however old, absent when nothing is, and whether
    /// a lookup is due.
    fn release(
        &self,
        runtime: &dyn RuntimeAdapter,
        now: Timestamp,
        look_up: bool,
    ) -> (Fact<LatestRelease>, bool) {
        let Some(url) = runtime.release_source() else {
            return (Fact::NotProvided, false);
        };
        // No `config.toml` is the default, lookups on; one enclos cannot
        // read looks nothing up.
        let on = match self.layout.read_config() {
            Ok(text) => config::looks_up_releases(&text),
            Err(LayoutError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.to_string()),
        };
        match on {
            Ok(true) => {}
            Ok(false) => return (Fact::NotProvided, false),
            Err(why) => {
                let why = format!("nothing was looked up: {why}");
                return (Fact::CannotTell(why), false);
            }
        }
        let path = self.layout.runtime_releases();
        let mut kept = read_kept(&path);
        let kind = runtime.kind().as_str();
        let now = now.as_second();
        if !look_up {
            return match kept.remove(kind) {
                Some(lookup) => {
                    let due = !lookup.fresh(now);
                    (found(lookup, runtime), due)
                }
                None => (Fact::Absent, true),
            };
        }
        let lookup = match kept.get(kind).filter(|l| l.fresh(now)) {
            Some(lookup) => lookup.clone(),
            None => {
                let lookup = match self.look_up(url, runtime, &path) {
                    Ok(version) => Lookup {
                        at: now,
                        version: Some(version.as_str().to_owned()),
                        failed: None,
                    },
                    Err(why) => Lookup {
                        at: now,
                        version: None,
                        failed: Some(why),
                    },
                };
                kept.insert(kind.to_owned(), lookup.clone());
                // Not kept, each `status` would wait on the network: said.
                // The file's name, not its path: the path comes from the
                // engine, which code scanning takes for secret.
                if let Err(e) = write_kept(&path, &kept) {
                    eprintln!(
                        "enclos: cannot write {KEPT}, in enclos's data folder: {e}; each `enclos status` looks the releases up again"
                    );
                }
                lookup
            }
        };
        (found(lookup, runtime), false)
    }

    /// Looks the latest release up at `url`, the answer downloaded beside
    /// `kept` and removed once read.
    fn look_up(
        &self,
        url: &str,
        runtime: &dyn RuntimeAdapter,
        kept: &Path,
    ) -> Result<RuntimeVersion, String> {
        let answer = kept.with_extension(format!("{}.{}", runtime.kind(), std::process::id()));
        let fetched = self.downloader.lookup(url, &answer);
        let text = fetched
            .map_err(|failed| match failed {
                DownloadFailed::NotRun(why) | DownloadFailed::Ended(why) => why,
                DownloadFailed::NotHttps => "the answer was not on HTTPS".into(),
            })
            .and_then(|()| read_answer(&answer));
        let _ = std::fs::remove_file(&answer);
        let named = runtime.release_version(&text?)?;
        RuntimeVersion::new(&named)
            .ok_or_else(|| "the latest release is not named as a version".to_owned())
    }
}

/// What a lookup, kept or made now, says of `runtime`'s latest release.
fn found(lookup: Lookup, runtime: &dyn RuntimeAdapter) -> Fact<LatestRelease> {
    match (
        lookup.version.as_deref().and_then(RuntimeVersion::new),
        lookup.failed,
    ) {
        (Some(version), _) => Fact::Known(LatestRelease {
            checked: runtime.checked_releases().contains(&version.as_str()),
            version: version.as_str().to_owned(),
        }),
        (None, Some(why)) => Fact::CannotTell(why),
        (None, None) => Fact::CannotTell("the kept release is not a version".into()),
    }
}

fn read_answer(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read the answer: {e}"))?;
    if bytes.len() as u64 > LOOKUP_MAX_BYTES {
        return Err("the answer was too large".into());
    }
    String::from_utf8(bytes).map_err(|_| "the answer is not text".into())
}

/// What is kept, by runtime. A missing file keeps nothing, and so does one
/// that does not parse, which the next lookup replaces; one that cannot be
/// read is said, since the next write may fail the same way.
fn read_kept(path: &Path) -> BTreeMap<String, Lookup> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(e) if e.kind() == ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => {
            eprintln!("enclos: cannot read {KEPT}, in enclos's data folder: {e}");
            BTreeMap::new()
        }
    }
}

/// Writes what is kept in place of the file, whole: another `status` reads
/// the old file or the new one, never part of one. A partial file left by
/// a failed write or rename is removed.
fn write_kept(path: &Path, kept: &BTreeMap<String, Lookup>) -> std::io::Result<()> {
    let text = serde_json::to_vec_pretty(kept).map_err(std::io::Error::other)?;
    let partial = path.with_extension(format!("json.{}", std::process::id()));
    std::fs::write(&partial, text)
        .and_then(|()| std::fs::rename(&partial, path))
        .inspect_err(|_| {
            // Gone already, or never made: nothing more to do.
            let _ = std::fs::remove_file(&partial);
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_found_release_is_kept_longer_than_a_failure_and_a_future_time_is_not_trusted() {
        let found = |at| Lookup {
            at,
            version: Some("0.23.2".into()),
            failed: None,
        };
        let failed = |at| Lookup {
            at,
            version: None,
            failed: Some("no answer".into()),
        };
        let now = 1_000_000;
        assert!(found(now - 3600).fresh(now));
        assert!(!found(now - KEEP_FOUND).fresh(now));
        assert!(failed(now - 60).fresh(now));
        assert!(!failed(now - 3600).fresh(now));
        assert!(!found(now + 60).fresh(now));
    }

    #[test]
    fn kept_releases_are_read_back_and_a_damaged_file_keeps_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime-releases.json");
        assert!(read_kept(&path).is_empty());
        let mut kept = BTreeMap::new();
        kept.insert(
            "hermes".to_owned(),
            Lookup {
                at: 5,
                version: Some("0.23.2".into()),
                failed: None,
            },
        );
        write_kept(&path, &kept).unwrap();
        assert_eq!(read_kept(&path), kept);
        std::fs::write(&path, "{").unwrap();
        assert!(read_kept(&path).is_empty());
    }
}
