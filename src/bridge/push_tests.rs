use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, OnceLock};

use enclos_protocol::preview::open;
use ring::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

use super::*;
use crate::bridge::store::Device;

/// A PEM PKCS #8 RSA key of `bits`, made by `openssl` for the test: no
/// private key is kept in the repository.
fn rsa_pem(bits: u32) -> String {
    let made = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            &format!("rsa_keygen_bits:{bits}"),
        ])
        .output()
        .expect("openssl runs");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    String::from_utf8(made.stdout).unwrap()
}

fn pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| rsa_pem(2048))
}

fn key_json(pem: &str) -> Vec<u8> {
    serde_json::json!({
        "type": "service_account",
        "project_id": "enclos-test",
        "private_key_id": "0123",
        "private_key": pem,
        "client_email": "push@enclos-test.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string()
    .into_bytes()
}

fn with(field: &str, value: serde_json::Value) -> Vec<u8> {
    let mut json: serde_json::Value = serde_json::from_slice(&key_json(pem())).unwrap();
    json[field] = value;
    json.to_string().into_bytes()
}

#[test]
fn a_device_token_is_kept_only_when_it_is_an_fcm_token() {
    assert!(token_ok("fcm", "dQw4w9WgXcQ:APA91bH-x_y.z"));
    for (kind, token) in [
        ("apns", "abc"),
        ("fcm", ""),
        ("fcm", "has space"),
        ("fcm", "line\nbreak"),
        ("fcm", "é"),
    ] {
        assert!(!token_ok(kind, token), "{kind} {token:?}");
    }
    assert!(token_ok("fcm", &"a".repeat(MAX_TOKEN_BYTES)));
    assert!(!token_ok("fcm", &"a".repeat(MAX_TOKEN_BYTES + 1)));
}

#[test]
fn a_service_account_key_is_read_with_its_project_and_address() {
    let key = PushKey::parse(&key_json(pem())).unwrap();
    assert_eq!(key.project(), "enclos-test");
    assert_eq!(key.email(), "push@enclos-test.iam.gserviceaccount.com");
    // Its debug form names no secret.
    assert!(!format!("{key:?}").contains("PRIVATE"));
}

#[test]
fn anything_but_a_usable_service_account_key_is_refused() {
    let refused = |json: &[u8], why: &str| {
        let e = PushKey::parse(json).unwrap_err();
        assert!(e.contains(why), "{e}");
    };
    refused(b"not json", "not JSON");
    refused(&with("type", "authorized_user".into()), "`type`");
    refused(&with("type", serde_json::Value::Null), "`type`");
    for project in [
        "",
        "Enclos-Test",
        "short",
        "has_underscore",
        "ends-",
        "9starts",
    ] {
        refused(&with("project_id", project.into()), "`project_id`");
    }
    refused(&with("project_id", "../../x".into()), "`project_id`");
    refused(&with("client_email", "".into()), "`client_email`");
    refused(&with("client_email", "no at sign".into()), "`client_email`");
    refused(&with("private_key", "".into()), "`private_key`");
    refused(
        &with(
            "private_key",
            "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----".into(),
        ),
        "`private_key`",
    );
    // ring signs with RSA keys of 2048 bits or more only.
    refused(&key_json(&rsa_pem(1024)), "RSA key");
}

#[test]
fn the_assertion_asks_for_fcm_alone_for_an_hour_and_is_signed_by_the_key() {
    let key = PushKey::parse(&key_json(pem())).unwrap();
    let jwt = key.assertion(1_000_000).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let decode = |part: &str| -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    };
    assert_eq!(
        decode(parts[0]),
        serde_json::json!({"alg": "RS256", "typ": "JWT"})
    );
    assert_eq!(
        decode(parts[1]),
        serde_json::json!({
            "iss": "push@enclos-test.iam.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": 1_000_000,
            "exp": 1_003_600,
        })
    );
    let signed = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    UnparsedPublicKey::new(
        &RSA_PKCS1_2048_8192_SHA256,
        key.signer.public_key().as_ref(),
    )
    .verify(signed.as_bytes(), &signature)
    .unwrap();
}

#[test]
fn a_key_is_kept_for_the_user_alone_replaced_whole_and_removed() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("app-push-key.json");
    assert!(read_key(&path).unwrap().is_none());
    write_key(&path, &key_json(pem())).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(read_key(&path).unwrap().unwrap().project(), "enclos-test");
    // Another key takes its place.
    write_key(&path, &with("project_id", "enclos-other".into())).unwrap();
    assert_eq!(read_key(&path).unwrap().unwrap().project(), "enclos-other");
    // A refused one leaves it, and nothing beside it.
    assert!(write_key(&path, b"{}").is_err());
    assert_eq!(read_key(&path).unwrap().unwrap().project(), "enclos-other");
    assert_eq!(std::fs::read_dir(folder.path()).unwrap().count(), 1);
    assert!(remove_key(&path).unwrap());
    assert!(!remove_key(&path).unwrap());
    assert!(read_key(&path).unwrap().is_none());
}

#[test]
fn a_file_too_large_for_a_key_is_not_read_whole() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("big.json");
    std::fs::write(&path, vec![b' '; MAX_KEY_BYTES as usize + 1]).unwrap();
    assert!(read_bounded(&path).is_err());
    assert!(read_key(&path).is_err());
}

#[test]
fn fcm_answers_are_sorted_into_sent_gone_and_failed() {
    assert_eq!(
        outcome(200, r#"{"name":"projects/p/messages/1"}"#),
        Outcome::Sent
    );
    let fcm_error = |status: u16, code: &str, message: &str| {
        serde_json::json!({"error": {
            "code": status,
            "message": message,
            "status": "NOT_FOUND",
            "details": [{
                "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                "errorCode": code,
            }],
        }})
        .to_string()
    };
    assert_eq!(
        outcome(
            404,
            &fcm_error(404, "UNREGISTERED", "Requested entity was not found.")
        ),
        Outcome::Unregistered
    );
    let Outcome::Failed(why) = outcome(403, &fcm_error(403, "SENDER_ID_MISMATCH", "")) else {
        panic!()
    };
    assert!(why.contains("another Firebase project"), "{why}");
    assert_eq!(
        outcome(503, ""),
        Outcome::Failed("FCM answered 503".to_owned())
    );
    // Google's words are kept on one visible line, and short.
    let Outcome::Failed(why) = outcome(
        500,
        &fcm_error(500, "INTERNAL", &format!("a\nb\u{202E}{}", "x".repeat(500))),
    ) else {
        panic!()
    };
    assert!(why.starts_with("FCM answered 500 INTERNAL: a b"), "{why}");
    assert!(!why.contains(['\n', '\u{202E}']));
    assert_eq!(why.chars().count(), MAX_REASON_CHARS + 1);
}

fn job(device: &str, seq: i64) -> Job {
    Job {
        device: device.to_owned(),
        person: "alice@example.com".to_owned(),
        token: format!("token-{device}"),
        push_key: test_push_key(),
        seq,
        preview: br#"{"agent":"lab/main","conversation":"c-1","text":"hi"}"#.to_vec(),
    }
}

#[test]
fn a_push_carries_strings_alone_and_a_preview_only_its_device_opens() {
    let push = payload("mac", &job("d-1", 42)).unwrap();
    assert_eq!(
        push.request("token-1"),
        serde_json::json!({"message": {
            "token": "token-1",
            "data": {"v": "1", "host": "mac", "seq": "42", "preview": push.preview},
            "android": {"priority": "HIGH"},
        }})
    );
    let sealed = URL_SAFE_NO_PAD.decode(&push.preview).unwrap();
    // Every preview is the same size, whatever its text.
    assert_eq!(
        sealed.len(),
        URL_SAFE_NO_PAD
            .decode(
                payload(
                    "mac",
                    &Job {
                        preview: vec![b'x'; 900],
                        ..job("d-1", 42)
                    }
                )
                .unwrap()
                .preview
            )
            .unwrap()
            .len()
    );
    let fields = PushFields {
        host: "mac",
        seq: 42,
    };
    assert_eq!(
        open(&test_push_key(), &fields, &sealed).unwrap(),
        job("d-1", 42).preview
    );
    assert!(
        open(
            &crate::bridge::ids::random_bytes(32).unwrap(),
            &fields,
            &sealed
        )
        .is_err()
    );
    assert!(
        open(
            &test_push_key(),
            &PushFields {
                host: "mac",
                seq: 43
            },
            &sealed
        )
        .is_err()
    );
}

/// A push service that answers from a list and records what it was given.
struct Fake {
    answers: Arc<Mutex<Vec<Option<Outcome>>>>,
    sent: Arc<Mutex<Vec<(String, i64)>>>,
}

impl PushService for Fake {
    fn send(&mut self, token: &str, payload: &Payload) -> Option<Outcome> {
        self.sent
            .lock()
            .unwrap()
            .push((token.to_owned(), payload.seq));
        let mut answers = self.answers.lock().unwrap();
        if answers.is_empty() {
            Some(Outcome::Sent)
        } else {
            answers.remove(0)
        }
    }
}

fn device(id: &str) -> Device {
    Device {
        id: id.to_owned(),
        name: "Pixel".to_owned(),
        person: "alice@example.com".to_owned(),
        noise_key: vec![id.len() as u8; 32],
        device_key: vec![2; 32],
        push_key: test_push_key(),
        push_token: Some(format!("token-{id}")),
        paired: 1,
        seen: None,
        node: None,
    }
}

fn eventually(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn the_worker_records_each_outcome_with_its_device_and_logs_changes_once() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("app.db");
    let store = Store::open(&path).unwrap();
    store.add_device(&device("d-1")).unwrap();
    let failed = Outcome::Failed("FCM answered 503".to_owned());
    let answers = Arc::new(Mutex::new(vec![
        Some(failed.clone()),
        Some(failed.clone()),
        Some(Outcome::Sent),
        // No key: nothing is recorded.
        None,
        Some(Outcome::Unregistered),
    ]));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let pusher = Pusher::start(
        Box::new(Fake {
            answers: Arc::clone(&answers),
            sent: Arc::clone(&sent),
        }),
        "mac".to_owned(),
        path.clone(),
    );
    let events = |store: &Store| -> Vec<String> {
        store
            .log_lines(100)
            .unwrap()
            .into_iter()
            .map(|l| l.event)
            .collect()
    };
    let step = |seq: i64, done: &dyn Fn() -> bool| {
        pusher.push(job("d-1", seq));
        assert!(
            eventually(|| sent.lock().unwrap().len() as i64 >= seq && done()),
            "{seq}"
        );
    };
    step(1, &|| store.push_failure("d-1").unwrap().is_some());
    assert_eq!(
        store.push_failure("d-1").unwrap().as_deref(),
        Some("FCM answered 503")
    );
    step(2, &|| true);
    step(3, &|| store.push_failure("d-1").unwrap().is_none());
    step(4, &|| true);
    step(5, &|| {
        store.device("d-1").unwrap().unwrap().push_token.is_none()
    });
    // One line when it started failing, one when it worked again, one when
    // the token was dropped; none for the second failure alike.
    assert!(eventually(|| events(&store).len() == 3));
    assert_eq!(
        events(&store),
        ["push failed", "push working", "push token dropped"]
    );
}

#[test]
fn a_token_the_device_replaced_meanwhile_is_not_dropped() {
    let folder = tempfile::tempdir().unwrap();
    let store = Store::open(&folder.path().join("app.db")).unwrap();
    store.add_device(&device("d-1")).unwrap();
    store.set_push_token("d-1", "token-new").unwrap();
    assert!(!store.drop_push_token("d-1", "token-d-1").unwrap());
    assert_eq!(
        store.device("d-1").unwrap().unwrap().push_token.as_deref(),
        Some("token-new")
    );
}

#[test]
fn the_same_token_given_again_keeps_why_it_failed_and_a_new_one_clears_it() {
    let folder = tempfile::tempdir().unwrap();
    let store = Store::open(&folder.path().join("app.db")).unwrap();
    store.add_device(&device("d-1")).unwrap();
    store
        .set_push_failure("d-1", Some("FCM answered 503"))
        .unwrap();
    store.set_push_token("d-1", "token-d-1").unwrap();
    assert_eq!(
        store.push_failure("d-1").unwrap().as_deref(),
        Some("FCM answered 503")
    );
    store.set_push_token("d-1", "token-new").unwrap();
    assert_eq!(store.push_failure("d-1").unwrap(), None);
}

#[test]
fn pushes_waiting_together_go_once_per_device_the_newest_each() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("app.db");
    Store::open(&path).unwrap();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (jobs, waiting) = channel();
    for (d, seq) in [("d-1", 3), ("d-2", 1), ("d-1", 5), ("d-1", 4)] {
        jobs.send(job(d, seq)).unwrap();
    }
    drop(jobs);
    work(
        waiting,
        Box::new(Fake {
            answers: Arc::default(),
            sent: Arc::clone(&sent),
        }),
        "mac",
        &path,
    );
    let mut sent = sent.lock().unwrap().clone();
    sent.sort();
    assert_eq!(
        sent,
        [("token-d-1".to_owned(), 5), ("token-d-2".to_owned(), 1)]
    );
}

#[test]
fn a_running_bridge_takes_a_key_given_replaced_or_removed_without_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("app-push-key.json");
    let mut fcm = Fcm::new(path.clone());
    // No key: push is off, and nothing is tried.
    assert!(fcm.current_key().unwrap().is_none());
    assert!(
        fcm.send("token", &payload("mac", &job("d-1", 1)).unwrap())
            .is_none()
    );
    write_key(&path, &key_json(pem())).unwrap();
    assert_eq!(fcm.current_key().unwrap().unwrap().project(), "enclos-test");
    write_key(&path, &with("project_id", "enclos-other".into())).unwrap();
    assert_eq!(
        fcm.current_key().unwrap().unwrap().project(),
        "enclos-other"
    );
    remove_key(&path).unwrap();
    assert!(fcm.current_key().unwrap().is_none());
    // A file that is no key is a failure to show, not push turned off.
    std::fs::write(&path, b"{}").unwrap();
    assert!(fcm.current_key().is_err());
}
