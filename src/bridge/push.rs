//! Push through FCM (ADR 0065, proposed; `docs/protocol.md`,
//! Notifications): when a message reaches a person with no device
//! connected, the bridge sends each of their devices a data message that
//! holds the preview sealed for that device alone.
//!
//! The bridge signs in to Google as a service account whose key the host's
//! user gives it with `enclos app push key`, kept in `app-push-key.json`,
//! the user's alone, in a file no sandbox reads (`Layout::hidden_files`).
//! Without that file the bridge sends nothing. A worker thread does the
//! sending, so no device's session and no plugin waits on Google; it reads
//! the key again whenever the file changes, so a key given, replaced or
//! removed while the bridge runs counts from the next push.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use enclos_protocol::preview::{PushFields, seal};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use zeroize::Zeroizing;

use super::store::Store;

/// The most a key file may hold: a service-account key is about 2.4 KB.
pub const MAX_KEY_BYTES: u64 = 16 * 1024;

/// What Google's token endpoint is asked for: sending through FCM, nothing
/// more.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FCM_URL: &str = "https://fcm.googleapis.com/v1/projects";

/// How long a signed assertion, and so the access token it is exchanged
/// for, is asked to last; Google allows an hour at most.
const ASSERTION_SECONDS: u64 = 3600;

/// An access token is used until this long before it expires.
const TOKEN_MARGIN: Duration = Duration::from_secs(300);

/// How long one call to Google may take, connecting included.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// The most of Google's answer the bridge reads.
const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// The most of Google's reason a log line or `app status` keeps.
const MAX_REASON_CHARS: usize = 200;

/// The longest push token a device may give: FCM's are about 160
/// characters.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Whether a device's push token is one the bridge keeps: an FCM token, of
/// the characters FCM uses, at most [`MAX_TOKEN_BYTES`].
pub fn token_ok(kind: &str, token: &str) -> bool {
    kind == "fcm"
        && !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
}

/// A service-account key, read from the JSON file Google Cloud gives.
pub struct PushKey {
    project: String,
    email: String,
    signer: RsaKeyPair,
}

impl std::fmt::Debug for PushKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushKey")
            .field("project", &self.project)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl PushKey {
    /// Reads a service-account key file's JSON. Refuses anything else: a
    /// key of another type, an id that is not a Firebase project's, or a
    /// private key ring does not take as an RSA key of 2048 bits or more.
    pub fn parse(json: &[u8]) -> Result<PushKey, String> {
        // The fields the bridge uses; serde leaves the others. The private
        // key's text is zeroed once read; what the parser held on the way
        // is not.
        #[derive(serde::Deserialize)]
        struct KeyFile {
            #[serde(rename = "type")]
            kind: Option<String>,
            project_id: Option<String>,
            client_email: Option<String>,
            private_key: Option<String>,
        }
        let mut file: KeyFile = serde_json::from_slice(json)
            .map_err(|_| "it is not a service-account key: not JSON".to_owned())?;
        let pem = Zeroizing::new(file.private_key.take().unwrap_or_default());
        if file.kind.as_deref() != Some("service_account") {
            return Err(
                "it is not a service-account key: its `type` is not `service_account`".to_owned(),
            );
        }
        let project = file.project_id.unwrap_or_default();
        if !project_ok(&project) {
            return Err("its `project_id` is not a Google Cloud project id".to_owned());
        }
        let email = file.client_email.unwrap_or_default();
        if email.is_empty()
            || email.len() > 254
            || !email.bytes().all(|b| b.is_ascii_graphic())
            || !email.contains('@')
        {
            return Err("its `client_email` is not a service account's address".to_owned());
        }
        let der = pkcs8_der(&pem)
            .ok_or_else(|| "its `private_key` is not a PEM private key".to_owned())?;
        let signer = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| format!("its `private_key` is not an RSA key ring can sign with: {e}"))?;
        Ok(PushKey {
            project,
            email,
            signer,
        })
    }

    /// The Firebase project the key sends for.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The service account's address.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// A JWT that asks Google's token endpoint for an FCM access token
    /// (RFC 7523), issued at `now` (Unix seconds).
    fn assertion(&self, now: u64) -> Result<String, String> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": self.email,
                "scope": SCOPE,
                "aud": TOKEN_URL,
                "iat": now,
                "exp": now + ASSERTION_SECONDS,
            })
            .to_string(),
        );
        let signed = format!("{header}.{claims}");
        let mut signature = vec![0; self.signer.public().modulus_len()];
        self.signer
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| "cannot sign the request for an access token".to_owned())?;
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

/// A Google Cloud project id: 6 to 30 lower-case letters, digits and
/// hyphens, starting with a letter, not ending with a hyphen. It goes in
/// the address the bridge sends to.
fn project_ok(id: &str) -> bool {
    (6..=30).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The DER of a PEM `PRIVATE KEY` (PKCS #8).
fn pkcs8_der(pem: &str) -> Option<Zeroizing<Vec<u8>>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")?
        .strip_suffix("-----END PRIVATE KEY-----")?;
    let base64: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    STANDARD.decode(base64.as_bytes()).ok().map(Zeroizing::new)
}

/// The key kept at `path`; `None` when there is none.
pub fn read_key(path: &Path) -> Result<Option<PushKey>, String> {
    match read_bounded(path) {
        Ok(json) => PushKey::parse(&json)
            .map(Some)
            .map_err(|e| format!("{} cannot be used: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// The bytes of the file at `path`, of at most [`MAX_KEY_BYTES`].
pub fn read_bounded(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_KEY_BYTES {
        return Err(std::io::Error::other(format!(
            "it holds more than {MAX_KEY_BYTES} bytes, which no service-account key does"
        )));
    }
    Ok(bytes)
}

/// Keeps `json`, a service-account key [`PushKey::parse`] takes, at
/// `path`, the user's alone (0600), in place of any key there: written
/// whole beside it, then renamed over it, so the bridge never reads half a
/// key.
pub fn write_key(path: &Path, json: &[u8]) -> Result<PushKey, String> {
    let key = PushKey::parse(json)?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(
        ".{}.new",
        super::ids::new_id().map_err(|e| e.to_string())?
    ));
    let temporary = PathBuf::from(temporary);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(json)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(key)
}

/// Removes the key at `path`; whether there was one.
pub fn remove_key(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// What a push carries beside the token it goes to: FCM's data values,
/// all strings (`docs/protocol.md`, Notifications).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub host: String,
    pub seq: i64,
    /// `nonce ‖ ciphertext`, base64url.
    pub preview: String,
}

impl Payload {
    /// The FCM HTTP v1 request that sends it to `token`: a data message
    /// of high priority, and nothing Google would show itself.
    pub fn request(&self, token: &str) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "token": token,
                "data": {
                    "v": enclos_protocol::VERSION.to_string(),
                    "host": self.host,
                    "seq": self.seq.to_string(),
                    "preview": self.preview,
                },
                "android": {"priority": "HIGH"},
            }
        })
    }
}

/// What became of one push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// FCM no longer knows the token: the app was removed, or its data
    /// cleared. The bridge forgets it until the device gives a new one.
    Unregistered,
    /// Not sent, and why, in a line for `app status` and `app log`.
    Failed(String),
}

/// Where pushes go: FCM, or a stand-in in tests.
pub trait PushService: Send {
    /// Sends `payload` to `token`; `None` when no key is given, so push is
    /// off and nothing was tried.
    fn send(&mut self, token: &str, payload: &Payload) -> Option<Outcome>;
}

/// What FCM's answer `status`, `body` means for the push.
pub fn outcome(status: u16, body: &str) -> Outcome {
    if (200..300).contains(&status) {
        return Outcome::Sent;
    }
    let error: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let error = &error["error"];
    let code = error["details"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|d| d["errorCode"].as_str())
        .or_else(|| error["status"].as_str())
        .unwrap_or_default();
    let message = error["message"].as_str().unwrap_or_default();
    match code {
        "UNREGISTERED" => Outcome::Unregistered,
        "SENDER_ID_MISMATCH" => Outcome::Failed(
            "FCM refused it: the push key is for another Firebase project than the one the device's app uses (SENDER_ID_MISMATCH)"
                .to_owned(),
        ),
        _ => Outcome::Failed(reason(&format!(
            "FCM answered {status}{}{}",
            if code.is_empty() { String::new() } else { format!(" {code}") },
            if message.is_empty() { String::new() } else { format!(": {message}") },
        ))),
    }
}

/// `text` in one visible line of at most [`MAX_REASON_CHARS`].
fn reason(text: &str) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let line = enclos_protocol::visible::stripped(&line, false);
    match line.char_indices().nth(MAX_REASON_CHARS) {
        Some((at, _)) => format!("{}…", &line[..at]),
        None => line,
    }
}

/// FCM, signed in with the key at a path, read again whenever the file
/// changes.
pub struct Fcm {
    path: PathBuf,
    agent: ureq::Agent,
    /// The key as last read, with what identified the file then.
    key: Option<(FileStamp, Arc<PushKey>)>,
    /// An access token and when to stop using it.
    access: Option<(String, Instant)>,
}

/// What tells one version of the key file from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    inode: u64,
    modified: i64,
    modified_ns: i64,
    size: u64,
}

impl Fcm {
    pub fn new(path: PathBuf) -> Fcm {
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(CALL_TIMEOUT))
            .tls_config(tls)
            .build()
            .into();
        Fcm {
            path,
            agent,
            key: None,
            access: None,
        }
    }

    /// The key as the file holds it now; `Ok(None)` when there is none.
    fn current_key(&mut self) -> Result<Option<Arc<PushKey>>, String> {
        let stamp = match std::fs::metadata(&self.path) {
            Ok(m) => FileStamp {
                inode: m.ino(),
                modified: m.mtime(),
                modified_ns: m.mtime_nsec(),
                size: m.size(),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.key = None;
                self.access = None;
                return Ok(None);
            }
            Err(e) => return Err(format!("cannot read the push key: {e}")),
        };
        if let Some((kept, key)) = &self.key
            && *kept == stamp
        {
            return Ok(Some(Arc::clone(key)));
        }
        self.access = None;
        match read_key(&self.path)? {
            Some(key) => {
                let key = Arc::new(key);
                self.key = Some((stamp, Arc::clone(&key)));
                Ok(Some(key))
            }
            None => {
                self.key = None;
                Ok(None)
            }
        }
    }

    /// An access token, asked of Google when the one kept is near its end.
    fn access_token(&mut self, key: &PushKey) -> Result<String, String> {
        if let Some((token, until)) = &self.access
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let assertion = Zeroizing::new(key.assertion(now)?);
        let mut answer = self
            .agent
            .post(TOKEN_URL)
            .send_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .map_err(|e| reason(&format!("cannot reach Google for an access token: {e}")))?;
        let status = answer.status().as_u16();
        let body = Zeroizing::new(
            answer
                .body_mut()
                .with_config()
                .limit(MAX_ANSWER_BYTES)
                .read_to_string()
                .map_err(|e| reason(&format!("cannot read Google's answer: {e}")))?,
        );
        let value: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let (Some(token), true) = (value["access_token"].as_str(), status == 200) else {
            let why = value["error_description"]
                .as_str()
                .or_else(|| value["error"].as_str())
                .unwrap_or("no access token in its answer");
            return Err(reason(&format!(
                "Google refused the push key ({status}): {why}"
            )));
        };
        let lasts = Duration::from_secs(value["expires_in"].as_u64().unwrap_or(0));
        let until = Instant::now() + lasts.saturating_sub(TOKEN_MARGIN);
        self.access = Some((token.to_owned(), until));
        Ok(token.to_owned())
    }

    fn send_once(&mut self, key: &PushKey, token: &str, payload: &Payload) -> (Outcome, u16) {
        let access = match self.access_token(key) {
            Ok(access) => Zeroizing::new(access),
            Err(why) => return (Outcome::Failed(why), 0),
        };
        let url = format!("{FCM_URL}/{}/messages:send", key.project());
        let answer = self
            .agent
            .post(&url)
            .header("Authorization", format!("Bearer {}", access.as_str()))
            .header("Content-Type", "application/json; charset=utf-8")
            .send(payload.request(token).to_string());
        let mut answer = match answer {
            Ok(answer) => answer,
            Err(e) => {
                return (
                    Outcome::Failed(reason(&format!("cannot reach FCM: {e}"))),
                    0,
                );
            }
        };
        let status = answer.status().as_u16();
        let body = answer
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_string()
            .unwrap_or_default();
        (outcome(status, &body), status)
    }
}

impl PushService for Fcm {
    fn send(&mut self, token: &str, payload: &Payload) -> Option<Outcome> {
        let key = match self.current_key() {
            Ok(Some(key)) => key,
            Ok(None) => return None,
            Err(why) => return Some(Outcome::Failed(reason(&why))),
        };
        match self.send_once(&key, token, payload) {
            // The access token was refused before its time (revoked, or
            // the clock moved): once more with a new one.
            (_, 401) => {
                self.access = None;
                Some(self.send_once(&key, token, payload).0)
            }
            (outcome, _) => Some(outcome),
        }
    }
}

/// One push to make: a device, the token it gave, its `push_key`, and the
/// preview's plaintext (`docs/protocol.md`, Notifications).
#[derive(Clone, PartialEq, Eq)]
pub struct Job {
    pub device: String,
    pub person: String,
    pub token: String,
    pub push_key: Vec<u8>,
    pub seq: i64,
    pub preview: Vec<u8>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("device", &self.device)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// Hands pushes to the worker thread that sends them.
#[derive(Clone)]
pub struct Pusher {
    jobs: Sender<Job>,
}

impl Pusher {
    /// Starts the worker: it sends through `service`, names this host
    /// `host` in each push, and records what became of each in the
    /// bridge's database at `store_path`.
    pub fn start(service: Box<dyn PushService>, host: String, store_path: PathBuf) -> Pusher {
        let (jobs, waiting) = channel();
        std::thread::Builder::new()
            .name("enclos-push".to_owned())
            .spawn(move || work(waiting, service, &host, &store_path))
            .expect("a thread starts");
        Pusher { jobs }
    }

    pub fn push(&self, job: Job) {
        let _ = self.jobs.send(job);
    }
}

fn work(waiting: Receiver<Job>, mut service: Box<dyn PushService>, host: &str, store: &Path) {
    while let Ok(first) = waiting.recv() {
        // The newest for each device of those waiting: a phone shows the
        // last message, then syncs the rest, so one push per device does.
        let mut newest: HashMap<String, Job> = HashMap::new();
        for job in std::iter::once(first).chain(waiting.try_iter()) {
            match newest.get(&job.device) {
                Some(kept) if kept.seq >= job.seq => {}
                _ => {
                    newest.insert(job.device.clone(), job);
                }
            }
        }
        for job in newest.into_values() {
            let outcome = match payload(host, &job) {
                Ok(payload) => service.send(&job.token, &payload),
                Err(why) => Some(Outcome::Failed(why)),
            };
            if let Some(outcome) = outcome {
                record(store, &job, &outcome);
            }
        }
    }
}

/// The push for `job`: its preview sealed under the device's `push_key`,
/// bound to this host and `seq`.
pub fn payload(host: &str, job: &Job) -> Result<Payload, String> {
    let sealed = seal(
        &job.push_key,
        &PushFields { host, seq: job.seq },
        &job.preview,
    )
    .map_err(|e| format!("cannot seal the preview: {e}"))?;
    Ok(Payload {
        host: host.to_owned(),
        seq: job.seq,
        preview: URL_SAFE_NO_PAD.encode(sealed),
    })
}

/// Keeps what became of `job` with its device, and in the bridge's log
/// when that changed: a device that keeps failing logs once, not once a
/// message.
fn record(path: &Path, job: &Job, outcome: &Outcome) {
    let store = match Store::open(path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!(
                "enclos app: a push to {} went {outcome:?}, but the bridge's database cannot be opened to record it: {e}",
                job.device
            );
            return;
        }
    };
    let before = store.push_failure(&job.device).ok().flatten();
    let result = match outcome {
        Outcome::Sent => store.set_push_failure(&job.device, None).and_then(|()| {
            if before.is_some() {
                store.log(Some(&job.device), Some(&job.person), "push working", None)?;
            }
            Ok(())
        }),
        Outcome::Unregistered => {
            store
                .drop_push_token(&job.device, &job.token)
                .and_then(|dropped| {
                    if dropped {
                        store.log(
                        Some(&job.device),
                        Some(&job.person),
                        "push token dropped",
                        Some("FCM no longer knows it: the device sends a new one when it connects"),
                    )?;
                    }
                    Ok(())
                })
        }
        Outcome::Failed(why) => store
            .set_push_failure(&job.device, Some(why))
            .and_then(|()| {
                if before.as_deref() != Some(why.as_str()) {
                    store.log(
                        Some(&job.device),
                        Some(&job.person),
                        "push failed",
                        Some(why),
                    )?;
                }
                Ok(())
            }),
    };
    if let Err(e) = result {
        eprintln!(
            "enclos app: a push to {} went {outcome:?}, but it cannot be recorded: {e}",
            job.device
        );
    }
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
