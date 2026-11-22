//! Per-sandbox artefacts folder (ADR 0078, proposed; `docs/protocol.md`,
//! Artefacts): the bridge reads `<sandbox home>/.enclos-app/artefacts/`
//! component by component without following a link, lists eligible files
//! newest-first within its count and total-size bounds, and serves each
//! fetch from a per-fetch copy in its own folder, never from the sandbox's
//! path.
//!
//! Audience rule: list and fetch go to any person the bridge lists at least
//! one agent of that sandbox to. Today the bridge has one person (the
//! host's person) and serves every agent to them, so the `artefacts`
//! capability is advertised to every person and a request is refused
//! `not_allowed` when the bridge serves no agent of that sandbox.

use std::collections::HashSet;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use enclos_protocol::device::Artefact;
use rustix::fs::{Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::*;
use crate::runtime::NotRead;
use crate::runtime::home::{is_dot, wide};

/// The largest artefact the bridge lists or serves: 25 MiB, as attachments.
pub(super) const MAX_ARTEFACT_BYTES: u64 = MAX_ATTACHMENT_BYTES;

/// The most artefacts listed for one sandbox; older ones are left out.
pub(super) const MAX_ARTEFACTS: usize = 256;

/// The largest live total of eligible artefacts listed for one sandbox:
/// 1 GiB; the first file that would carry the sum past it and everything
/// after it are left out.
pub(super) const MAX_ARTEFACT_TOTAL: u64 = 1024 * 1024 * 1024;

/// The most directory entries read in one walk of an artefacts folder.
pub(super) const MAX_ARTEFACT_ENTRIES: usize = 4096;

/// Exact length of an artefact id (base64url-encoded SHA-256 prefix).
const ARTEFACT_ID_LEN: usize = 22;

/// The longest sandbox name accepted in an artefacts request.
const MAX_SANDBOX_CHARS: usize = 128;

/// Uniform refusal message for missing, unserved or ineligible artefacts.
const NO_SUCH_ARTEFACT: &str = "no such artefact";

/// Identity of an opened file in the sandbox's artefacts folder, checked
/// before every part is served from a fetch copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: i128,
    ino: i128,
    size: i128,
    mtime: i128,
}

impl FileIdentity {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            dev: wide(stat.st_dev),
            ino: wide(stat.st_ino),
            size: wide(stat.st_size),
            mtime: wide(stat.st_mtime),
        }
    }
}

/// One per-fetch copy held in the bridge's `app-artefact-copies/` folder
/// for the life of the device connection (or until a second fetch starts).
pub(super) struct FetchCopy {
    sandbox: String,
    artefact: String,
    name: String,
    identity: FileIdentity,
    path: PathBuf,
    size: u64,
    sha256: String,
}

impl Drop for FetchCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An eligible file found during a folder walk, before count/total limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Candidate {
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) arrived: u64,
}

/// Why an eligible file was left out of the listing by a sandbox limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExcludedReason {
    CountLimit { limit: usize },
    TotalLimit { used: u64, limit: u64 },
}

/// An eligible file excluded from the listing by a sandbox limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Excluded {
    pub(super) name: String,
    pub(super) reason: ExcludedReason,
}

/// Stable bridge id for an artefact name within `sandbox`:
/// `base64url(sha256(sandbox || 0x00 || name))` truncated to 22 characters,
/// with no padding. Identifies a name in its sandbox, never content or a
/// path.
pub(super) fn artefact_id(sandbox: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sandbox.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    let mut encoded = encode(&hasher.finalize());
    encoded.truncate(ARTEFACT_ID_LEN);
    encoded
}

/// Whether `id` has the exact shape of an artefact id: 22 unpadded
/// base64url characters (`A-Za-z0-9-_`).
pub(super) fn valid_artefact_id(id: &str) -> bool {
    id.len() == ARTEFACT_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Whether `sandbox` is a syntactically valid sandbox name for a request.
fn valid_sandbox(sandbox: &str) -> bool {
    !sandbox.is_empty() && sandbox.chars().count() <= MAX_SANDBOX_CHARS
}

/// Whether `name` is an eligible file name of the artefacts folder.
fn eligible_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !enclos_protocol::visible::has_hidden(name, false)
        && name.chars().count() <= MAX_ATTACHMENT_NAME_CHARS
}

/// Derives a plain lower-case `type/subtype` media type from `name`'s
/// extension alone (last `.` not at index 0, case-insensitive): checks
/// `enclos_protocol::incoming::FILE_TYPES`, plus `.html`/`.htm` and `.apk`,
/// falling back to `application/octet-stream`.
pub(super) fn artefact_mime(name: &str) -> String {
    let Some(dot) = name.rfind('.').filter(|&at| at > 0) else {
        return "application/octet-stream".to_owned();
    };
    let ext = &name[dot..];
    if let Some((_, mime, _)) = enclos_protocol::incoming::FILE_TYPES
        .iter()
        .find(|(known, _, _)| known.eq_ignore_ascii_case(ext))
    {
        return attachment_mime(mime);
    }
    if ext.eq_ignore_ascii_case(".html") || ext.eq_ignore_ascii_case(".htm") {
        return attachment_mime("text/html");
    }
    if ext.eq_ignore_ascii_case(".apk") {
        return attachment_mime("application/vnd.android.package-archive");
    }
    "application/octet-stream".to_owned()
}

/// Orders eligible files newest-first (ties by `name` ascending) and
/// applies the 256-file count limit and 1 GiB total-size limit in order.
/// The first file that would carry the total past 1 GiB and every file
/// after it are left out. Pure so limits are unit-testable with synthetic
/// sizes.
pub(super) fn apply_limits(mut candidates: Vec<Candidate>) -> (Vec<Candidate>, Vec<Excluded>) {
    candidates.sort_by(|a, b| b.arrived.cmp(&a.arrived).then_with(|| a.name.cmp(&b.name)));
    let mut kept = Vec::new();
    let mut excluded = Vec::new();
    let mut total: u64 = 0;
    let mut over_total = false;
    for candidate in candidates {
        if kept.len() >= MAX_ARTEFACTS {
            excluded.push(Excluded {
                name: candidate.name,
                reason: ExcludedReason::CountLimit {
                    limit: MAX_ARTEFACTS,
                },
            });
            continue;
        }
        if over_total || total.saturating_add(candidate.size) > MAX_ARTEFACT_TOTAL {
            over_total = true;
            excluded.push(Excluded {
                name: candidate.name,
                reason: ExcludedReason::TotalLimit {
                    used: total,
                    limit: MAX_ARTEFACT_TOTAL,
                },
            });
            continue;
        }
        total += candidate.size;
        kept.push(candidate);
    }
    (kept, excluded)
}

/// Formats one limit-exclusion log line.
pub(super) fn exclusion_line(excluded: &Excluded) -> String {
    let shown = enclos_protocol::visible::revealed(&excluded.name);
    let path = format!("~/{}/{shown}", ARTEFACTS.join("/"));
    match excluded.reason {
        ExcludedReason::CountLimit { limit } => {
            format!("enclos app: {path} is left out: more than {limit} artefacts")
        }
        ExcludedReason::TotalLimit { used, .. } => {
            format!("enclos app: {path} is left out: total in use ({used} bytes) exceeds 1 GiB")
        }
    }
}

/// Splits `files` into one or more `artefacts.list` frames that each fit
/// one device-leg message, keeping newest entries first and repeating `of`,
/// `sandbox` and `count` on every frame.
pub(super) fn list_frames(of: &MessageId, sandbox: &str, files: Vec<Artefact>) -> Vec<ToDevice> {
    let count = u32::try_from(files.len()).unwrap_or(u32::MAX);
    if files.is_empty() {
        return vec![ToDevice::ArtefactsList {
            of: of.clone(),
            sandbox: sandbox.to_owned(),
            count: 0,
            files: Vec::new(),
        }];
    }
    let whole = ToDevice::ArtefactsList {
        of: of.clone(),
        sandbox: sandbox.to_owned(),
        count,
        files,
    };
    if fits_device(&whole) {
        return vec![whole];
    }
    let ToDevice::ArtefactsList { files, .. } = whole else {
        unreachable!();
    };
    let mut frames = Vec::new();
    let mut current: Vec<Artefact> = Vec::new();
    for file in files {
        current.push(file);
        let candidate = ToDevice::ArtefactsList {
            of: of.clone(),
            sandbox: sandbox.to_owned(),
            count,
            files: current.clone(),
        };
        if !fits_device(&candidate) {
            let last = current.pop().expect("just pushed");
            if !current.is_empty() {
                frames.push(ToDevice::ArtefactsList {
                    of: of.clone(),
                    sandbox: sandbox.to_owned(),
                    count,
                    files: std::mem::take(&mut current),
                });
            }
            current.push(last);
        }
    }
    if !current.is_empty() {
        frames.push(ToDevice::ArtefactsList {
            of: of.clone(),
            sandbox: sandbox.to_owned(),
            count,
            files: current,
        });
    }
    frames
}

/// Removes every leftover per-fetch artefact copy when the bridge starts.
pub(super) fn sweep_copies(copies_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(copies_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Err(e) = std::fs::remove_file(&path) {
            eprintln!("enclos app: {}: {e}", path.display());
        }
    }
}

/// Resolves `sandbox`'s home from enclos's own socket path of a served
/// agent of that sandbox, never by joining the device's text onto a path.
fn served_sandbox_home(hub: &Hub, sandbox: &str) -> Option<PathBuf> {
    let agents = hub.agents();
    let endpoint = agents
        .iter()
        .find(|a| a.name.split_once('/').is_some_and(|(sb, _)| sb == sandbox))?;
    let home = sandbox_home(&endpoint.socket);
    (!home.as_os_str().is_empty()).then_some(home)
}

/// Opens `<home>/.enclos-app/artefacts` one component at a time without
/// following a link. `Ok(None)` when the home or either folder is missing.
fn open_artefacts(home: &Path) -> Result<Option<OwnedFd>, String> {
    let mut dir = match open_home(home) {
        Ok(fd) => fd,
        Err(e) if e.why == NotRead::Missing => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut shown = "~".to_owned();
    for name in ARTEFACTS {
        shown = format!("{shown}/{name}");
        match open_folder(&dir, name, &shown) {
            Ok(Some(next)) => dir = next,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(Some(dir))
}

/// Records a refusal once per `(sandbox, file, reason)` per bridge run and
/// writes it to stderr. Returns the logged line when it is new.
fn log_once(
    seen: &Mutex<HashSet<String>>,
    sandbox: &str,
    file: &str,
    reason: &str,
    line: String,
) -> Option<String> {
    let key = format!("{sandbox}\0{file}\0{reason}");
    let mut set = seen.lock().expect("not poisoned");
    if set.insert(key) {
        eprintln!("{line}");
        Some(line)
    } else {
        None
    }
}

fn arrived_from_stat(stat: &Stat) -> u64 {
    let secs = wide(stat.st_mtime);
    u64::try_from(secs.max(0)).unwrap_or(0)
}

/// Opens one entry of `dir` without following a link or blocking, and
/// checks that it is a regular file with `st_nlink == 1` and size within
/// `MAX_ARTEFACT_BYTES`. Returns the reason string on refusal.
fn open_eligible_file(dir: &OwnedFd, name: &str) -> Result<(OwnedFd, Stat), &'static str> {
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err("is not a file"),
        Err(_) => return Err("is not a file"),
    };
    let stat = rustix::fs::fstat(&fd).map_err(|_| "is not a file")?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err("is not a file");
    }
    // A second link may be one to a host file the sandbox could not read.
    if stat.st_nlink != 1 {
        return Err("has other links to it");
    }
    if stat.st_size < 0 || stat.st_size as u64 > MAX_ARTEFACT_BYTES {
        return Err("is larger than 25 MiB");
    }
    Ok((fd, stat))
}

/// Walks `<home>/.enclos-app/artefacts/` for `sandbox`, applying name,
/// file-kind, link-count, size, entry-count, count and total-size rules.
/// Returns the ordered list of artefacts and any new refusal lines written
/// to stderr during this walk.
pub(super) fn walk_sandbox(
    sandbox: &str,
    home: &Path,
    seen: &Mutex<HashSet<String>>,
) -> (Vec<Artefact>, Vec<String>) {
    let (kept, logged) = walk_kept(sandbox, home, seen);
    let artefacts = kept
        .into_iter()
        .map(|c| Artefact {
            id: artefact_id(sandbox, &c.name),
            mime: artefact_mime(&c.name),
            name: c.name,
            size: c.size,
            arrived: c.arrived,
        })
        .collect();
    (artefacts, logged)
}

/// Walks `<home>/.enclos-app/artefacts/` for `sandbox`: the files the
/// count and total-size limits keep, newest first, and any new refusal
/// lines written to stderr. A fetch resolves its id in this same set, so
/// what the bridge serves is exactly what it lists, and the size limits
/// cannot be worked around by asking for an id directly.
fn walk_kept(
    sandbox: &str,
    home: &Path,
    seen: &Mutex<HashSet<String>>,
) -> (Vec<Candidate>, Vec<String>) {
    let mut logged = Vec::new();
    let dir = match open_artefacts(home) {
        Ok(Some(dir)) => dir,
        Ok(None) => return (Vec::new(), logged),
        Err(why) => {
            let line = format!("enclos app: ~/{}: {why}", ARTEFACTS.join("/"));
            if let Some(l) = log_once(seen, sandbox, "", &why, line) {
                logged.push(l);
            }
            return (Vec::new(), logged);
        }
    };
    let entries = match Dir::read_from(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            let why = e.to_string();
            let line = format!("enclos app: ~/{}: {why}", ARTEFACTS.join("/"));
            if let Some(l) = log_once(seen, sandbox, "", &why, line) {
                logged.push(l);
            }
            return (Vec::new(), logged);
        }
    };

    let prefix = ARTEFACTS.join("/");
    let mut candidates = Vec::new();
    let mut read_count = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let why = e.to_string();
                let line = format!("enclos app: ~/{prefix}: {why}");
                if let Some(l) = log_once(seen, sandbox, "", &why, line) {
                    logged.push(l);
                }
                break;
            }
        };
        let raw_name = entry.file_name();
        if is_dot(raw_name) {
            continue;
        }
        read_count += 1;
        if read_count > MAX_ARTEFACT_ENTRIES {
            let reason = format!("has more than {MAX_ARTEFACT_ENTRIES} entries");
            let line = format!("enclos app: ~/{prefix} {reason}; stopping");
            if let Some(l) = log_once(seen, sandbox, "", &reason, line) {
                logged.push(l);
            }
            break;
        }
        let Ok(name) = raw_name.to_str() else {
            let lossy = String::from_utf8_lossy(raw_name.to_bytes());
            let shown = enclos_protocol::visible::revealed(&lossy);
            let reason = "is not a name of the folder";
            let line = format!("enclos app: ~/{prefix}/{shown} {reason}");
            if let Some(l) = log_once(seen, sandbox, &shown, reason, line) {
                logged.push(l);
            }
            continue;
        };
        if !eligible_name(name) {
            let shown = enclos_protocol::visible::revealed(name);
            let reason = "is not a name of the folder";
            let line = format!("enclos app: ~/{prefix}/{shown} {reason}");
            if let Some(l) = log_once(seen, sandbox, &shown, reason, line) {
                logged.push(l);
            }
            continue;
        }
        match open_eligible_file(&dir, name) {
            Ok((_fd, stat)) => {
                candidates.push(Candidate {
                    name: name.to_owned(),
                    size: stat.st_size as u64,
                    arrived: arrived_from_stat(&stat),
                });
            }
            Err(reason) => {
                let shown = enclos_protocol::visible::revealed(name);
                let line = format!("enclos app: ~/{prefix}/{shown} {reason}");
                if let Some(l) = log_once(seen, sandbox, name, reason, line) {
                    logged.push(l);
                }
            }
        }
    }

    let (kept, excluded) = apply_limits(candidates);
    for ex in &excluded {
        let reason_key = match ex.reason {
            ExcludedReason::CountLimit { .. } => "count_limit",
            ExcludedReason::TotalLimit { .. } => "total_limit",
        };
        let line = exclusion_line(ex);
        if let Some(l) = log_once(seen, sandbox, &ex.name, reason_key, line) {
            logged.push(l);
        }
    }

    (kept, logged)
}

/// Resolves an artefact id in `<home>/.enclos-app/artefacts/` by walking
/// the folder and comparing derived ids, never by joining a path from the
/// device's text, and only among the files the listing would publish.
/// Returns the matched file's name, open descriptor and `fstat` when
/// eligible.
fn resolve_id(
    sandbox: &str,
    home: &Path,
    seen: &Mutex<HashSet<String>>,
    target_id: &str,
) -> Option<(String, OwnedFd, Stat)> {
    let (kept, _) = walk_kept(sandbox, home, seen);
    let name = kept
        .iter()
        .find(|c| artefact_id(sandbox, &c.name) == target_id)?
        .name
        .clone();
    let dir = open_artefacts(home).ok()??;
    let (fd, stat) = open_eligible_file(&dir, &name).ok()?;
    Some((name, fd, stat))
}

/// Copies `source` into the new file `to`, hashing it with SHA-256 as it
/// copies, bounded at `max` bytes. Refuses a file that grows past `max`
/// while copying, removing the partial copy on any error.
fn copy_and_hash(mut source: impl Read, to: &Path, max: u64) -> Result<(u64, String), CopyError> {
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)
        .map_err(|e| CopyError::Internal(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    let result = loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break Ok((size, encode(&hasher.finalize()))),
            Ok(read) => read,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break Err(CopyError::Refused),
        };
        size += read as u64;
        if size > max {
            break Err(CopyError::Refused);
        }
        hasher.update(&buffer[..read]);
        if let Err(e) = target.write_all(&buffer[..read]) {
            break Err(CopyError::Internal(e.to_string()));
        }
    };
    drop(target);
    if result.is_err() {
        let _ = std::fs::remove_file(to);
    }
    result
}

enum CopyError {
    Refused,
    Internal(String),
}

fn send_error(
    link: &mut Link,
    asked: MessageId,
    code: ErrorCode,
    message: impl Into<String>,
) -> Result<(), String> {
    link.send(ToDevice::Error(ErrorBody {
        of: Some(asked),
        code,
        message: message.into(),
    }))
}

/// Handles `FromDevice::Artefacts`: lists eligible files in `sandbox`'s
/// artefacts folder in one or more frames within the device byte budget.
pub(super) fn list(
    hub: &Arc<Hub>,
    link: &mut Link,
    sandbox: &str,
    asked: MessageId,
) -> Result<(), String> {
    if !valid_sandbox(sandbox) {
        return send_error(
            link,
            asked,
            ErrorCode::BadMessage,
            "A sandbox name is 1 to 128 characters.",
        );
    }
    let Some(home) = served_sandbox_home(hub, sandbox) else {
        return send_error(link, asked, ErrorCode::NotAllowed, NO_SUCH_ARTEFACT);
    };
    let (files, _) = walk_sandbox(sandbox, &home, &hub.artefact_refusals);
    for frame in list_frames(&asked, sandbox, files) {
        link.send(frame)?;
    }
    Ok(())
}

/// Handles `FromDevice::ArtefactGet`: serves one `ATTACHMENT_CHUNK` part
/// from a per-fetch copy in `app-artefact-copies/`, re-checking the
/// folder's file identity on every request.
pub(super) fn get(
    hub: &Arc<Hub>,
    link: &mut Link,
    fetch: &mut Option<FetchCopy>,
    sandbox: &str,
    artefact: &str,
    offset: u64,
    asked: MessageId,
) -> Result<(), String> {
    if !valid_sandbox(sandbox) || !valid_artefact_id(artefact) {
        return send_error(
            link,
            asked,
            ErrorCode::BadMessage,
            "Invalid sandbox or artefact id.",
        );
    }
    let Some(home) = served_sandbox_home(hub, sandbox) else {
        return send_error(link, asked, ErrorCode::NotAllowed, NO_SUCH_ARTEFACT);
    };

    let Some((name, fd, stat)) = resolve_id(sandbox, &home, &hub.artefact_refusals, artefact)
    else {
        if fetch
            .as_ref()
            .is_some_and(|f| f.sandbox == sandbox && f.artefact == artefact)
        {
            *fetch = None;
        }
        return send_error(link, asked, ErrorCode::NotAllowed, NO_SUCH_ARTEFACT);
    };
    let current_identity = FileIdentity::from_stat(&stat);

    let matches_existing = fetch
        .as_ref()
        .is_some_and(|f| f.sandbox == sandbox && f.artefact == artefact);

    if matches_existing {
        let same_file = fetch
            .as_ref()
            .is_some_and(|f| f.name == name && f.identity == current_identity);
        if !same_file {
            *fetch = None;
            return send_error(link, asked, ErrorCode::NotAllowed, NO_SUCH_ARTEFACT);
        }
        // We already have a valid copy for this exact file identity.
        drop(fd);
    } else {
        // Drop any previous fetch copy on this connection before starting a new one.
        *fetch = None;
        let copies_dir = hub.artefact_copies();
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&copies_dir)
        {
            eprintln!("enclos app: {}: {e}", copies_dir.display());
            return send_error(
                link,
                asked,
                ErrorCode::Internal,
                "The bridge could not copy the artefact.",
            );
        }
        let copy_id = match new_id() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("enclos app: cannot make artefact copy id: {e}");
                return send_error(
                    link,
                    asked,
                    ErrorCode::Internal,
                    "The bridge could not copy the artefact.",
                );
            }
        };
        let copy_path = copies_dir.join(copy_id);
        let source = std::fs::File::from(fd);
        let (size, sha256) = match copy_and_hash(source, &copy_path, MAX_ARTEFACT_BYTES) {
            Ok(ok) => ok,
            Err(CopyError::Refused) => {
                return send_error(link, asked, ErrorCode::NotAllowed, NO_SUCH_ARTEFACT);
            }
            Err(CopyError::Internal(e)) => {
                eprintln!("enclos app: cannot copy artefact: {e}");
                return send_error(
                    link,
                    asked,
                    ErrorCode::Internal,
                    "The bridge could not copy the artefact.",
                );
            }
        };
        *fetch = Some(FetchCopy {
            sandbox: sandbox.to_owned(),
            artefact: artefact.to_owned(),
            name,
            identity: current_identity,
            path: copy_path,
            size,
            sha256,
        });
    }

    let active = fetch.as_ref().expect("just set or verified");
    let mut file = match std::fs::File::open(&active.path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("enclos app: cannot read artefact copy: {e}");
            *fetch = None;
            return send_error(
                link,
                asked,
                ErrorCode::Internal,
                "The bridge could not read the artefact copy.",
            );
        }
    };
    let len = ATTACHMENT_CHUNK.min(active.size.saturating_sub(offset) as usize);
    let mut chunk = vec![0u8; len];
    if len > 0
        && let Err(e) = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut chunk))
    {
        eprintln!("enclos app: cannot read artefact copy: {e}");
        *fetch = None;
        return send_error(
            link,
            asked,
            ErrorCode::Internal,
            "The bridge could not read the artefact copy.",
        );
    }
    link.send(ToDevice::ArtefactData {
        of: asked,
        artefact: active.artefact.clone(),
        offset,
        size: active.size,
        sha256: active.sha256.clone(),
        data: encode(&chunk),
    })
}
