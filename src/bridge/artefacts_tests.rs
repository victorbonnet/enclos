//! Tests for the per-sandbox artefacts folder (ADR 0078, proposed).

use super::*;
use crate::bridge::server::artefacts::{
    Candidate, ExcludedReason, MAX_ARTEFACT_BYTES, MAX_ARTEFACT_TOTAL, MAX_ARTEFACTS, apply_limits,
    artefact_id, artefact_mime, exclusion_line, sweep_copies, walk_sandbox,
};
use enclos_protocol::device::{
    ARTEFACTS as ARTEFACTS_CAP, Artefact, FROM_DEVICE_TYPES, TO_DEVICE_TYPES, decode_from_device,
    decode_to_device,
};
use enclos_protocol::pairing::{decode, encode};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::os::unix::fs::symlink;
use std::sync::Mutex;

/// Builds a sandbox home at `<root>/<sandbox>/home`, creates its
/// `.enclos-app` folder, and returns an `AgentEndpoint` whose socket is
/// `<home>/.enclos-app/<agent>.sock` (as `Layout::agent_app_socket` puts it)
/// together with `<home>/.enclos-app/artefacts`.
fn sandbox_endpoint(root: &Path, sandbox: &str, agent: &str) -> (AgentEndpoint, PathBuf) {
    let home = root.join(sandbox).join("home");
    let app_dir = home.join(".enclos-app");
    std::fs::create_dir_all(&app_dir).unwrap();
    let artefacts_dir = app_dir.join("artefacts");
    let endpoint = AgentEndpoint {
        name: format!("{sandbox}/{agent}"),
        runtime: "hermes".to_owned(),
        socket: app_dir.join(format!("{agent}.sock")),
        token: TOKEN.to_owned(),
    };
    (endpoint, artefacts_dir)
}

/// Builds a test bridge serving `agents`.
fn bridge_for(root: &Path, agents: Vec<AgentEndpoint>) -> Bridge {
    bridge_built(
        root,
        SILENCE,
        Host::new(
            crate::layout::Layout::at(root.join("enclos")),
            "/unused/enclos".into(),
        ),
        agents,
        None,
    )
}

/// Sets `path`'s mtime to `secs` since the Unix epoch using `rustix::fs::utimensat`.
fn set_mtime(path: &Path, secs: i64) {
    let ts = rustix::fs::Timespec {
        tv_sec: secs,
        tv_nsec: 0,
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps {
            last_access: ts,
            last_modification: ts,
        },
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
}

/// Collects all `artefacts.list` frames answering one `artefacts` request.
fn receive_list(device: &mut PhoneLink, of: &str) -> (u32, Vec<Artefact>, usize) {
    let mut all = Vec::new();
    let mut frames = 0usize;
    let mut expected_count = 0u32;
    loop {
        match device.receive().expect("artefacts.list frame") {
            ToDevice::ArtefactsList {
                of: got_of,
                count,
                files,
                ..
            } => {
                assert_eq!(got_of.as_str(), of);
                if frames == 0 {
                    expected_count = count;
                } else {
                    assert_eq!(count, expected_count);
                }
                frames += 1;
                all.extend(files);
                if all.len() >= expected_count as usize {
                    return (expected_count, all, frames);
                }
            }
            other => panic!("expected artefacts.list, got {other:?}"),
        }
    }
}

#[test]
fn hand_dropped_files_are_listed_newest_first_with_ties_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    // Missing folder is an empty list, never an error.
    device.send(
        "l-0",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (count, files, frames) = receive_list(&mut device, "l-0");
    assert_eq!(count, 0);
    assert!(files.is_empty());
    assert_eq!(frames, 1);

    std::fs::create_dir_all(&artefacts_dir).unwrap();
    let f_old = artefacts_dir.join("report.HTML");
    let f_tie_b = artefacts_dir.join("beta.apk");
    let f_tie_a = artefacts_dir.join("alpha.png");
    let f_unknown = artefacts_dir.join("blob.custom");
    std::fs::write(&f_old, b"<h1>hi</h1>").unwrap();
    std::fs::write(&f_tie_b, b"apk-bytes").unwrap();
    std::fs::write(&f_tie_a, b"png!").unwrap();
    std::fs::write(&f_unknown, b"012345").unwrap();

    set_mtime(&f_old, 1_700_000_100);
    set_mtime(&f_tie_b, 1_700_000_200);
    set_mtime(&f_tie_a, 1_700_000_200);
    set_mtime(&f_unknown, 1_700_000_300);

    device.send(
        "l-1",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (count, files, _) = receive_list(&mut device, "l-1");
    assert_eq!(count, 4);
    assert_eq!(
        files
            .iter()
            .map(|f| (f.name.as_str(), f.mime.as_str(), f.size, f.arrived))
            .collect::<Vec<_>>(),
        vec![
            ("blob.custom", "application/octet-stream", 6, 1_700_000_300),
            ("alpha.png", "image/png", 4, 1_700_000_200),
            (
                "beta.apk",
                "application/vnd.android.package-archive",
                9,
                1_700_000_200,
            ),
            ("report.HTML", "text/html", 11, 1_700_000_100),
        ]
    );
    assert_eq!(artefact_mime("page.htm"), "text/html");
    assert_eq!(artefact_mime("noext"), "application/octet-stream");
}

#[test]
fn every_refusal_is_excluded_and_logged_once_per_bridge_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("lab").join("home");
    let artefacts_dir = home.join(".enclos-app").join("artefacts");
    std::fs::create_dir_all(&artefacts_dir).unwrap();

    // One valid file to confirm valid files still come through.
    std::fs::write(artefacts_dir.join("good.txt"), b"ok").unwrap();

    // 1. Symlink
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, b"secret").unwrap();
    symlink(&outside, artefacts_dir.join("link.txt")).unwrap();

    // 2. FIFO
    let fifo = artefacts_dir.join("pipe.fifo");
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    // 3. Directory
    std::fs::create_dir(artefacts_dir.join("subdir")).unwrap();

    // 4. Leading dot
    std::fs::write(artefacts_dir.join(".hidden"), b"dot").unwrap();

    // 5. Hidden character (BiDi override U+202E)
    std::fs::write(artefacts_dir.join("bad\u{202e}txt"), b"bidi").unwrap();

    // 6. Larger than 25 MiB (25 MiB + 1 byte sparse file)
    let big = std::fs::File::create(artefacts_dir.join("huge.bin")).unwrap();
    big.set_len(MAX_ARTEFACT_BYTES + 1).unwrap();

    // 7. Second hard link
    let linked = artefacts_dir.join("hardlinked.txt");
    std::fs::write(&linked, b"shared").unwrap();
    std::fs::hard_link(&linked, dir.path().join("other-link.txt")).unwrap();

    let seen = Mutex::new(HashSet::new());
    let (listed, first_log) = walk_sandbox("lab", &home, &seen);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "good.txt");

    // Every refusal is named once with the expected reason.
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/link.txt") && l.contains("is not a file")),
        "missing symlink refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/pipe.fifo") && l.contains("is not a file")),
        "missing FIFO refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/subdir") && l.contains("is not a file")),
        "missing directory refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/.hidden")
                && l.contains("is not a name of the folder")),
        "missing leading-dot refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("⟨U+202E⟩") && l.contains("is not a name of the folder")),
        "missing hidden-char refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/huge.bin")
                && l.contains("is larger than 25 MiB")),
        "missing size refusal: {first_log:?}"
    );
    assert!(
        first_log
            .iter()
            .any(|l| l.contains("~/.enclos-app/artefacts/hardlinked.txt")
                && l.contains("has other links to it")),
        "missing hard-link refusal: {first_log:?}"
    );
    assert_eq!(first_log.len(), 7, "expected 7 refusals: {first_log:?}");

    // A second walk of the same folder adds no second line.
    let (listed_again, second_log) = walk_sandbox("lab", &home, &seen);
    assert_eq!(listed_again.len(), 1);
    assert!(second_log.is_empty(), "second walk logged: {second_log:?}");
}

#[test]
fn count_and_total_limits_are_exclusions_named_in_the_log() {
    // 257 files: keep the newest 256 and name the oldest excluded one.
    let candidates: Vec<Candidate> = (0..=MAX_ARTEFACTS)
        .map(|i| Candidate {
            name: format!("file-{i:03}.txt"),
            size: 100,
            arrived: 1_700_000_000 + i as u64,
        })
        .collect();
    let (kept, excluded) = apply_limits(candidates);
    assert_eq!(kept.len(), MAX_ARTEFACTS);
    assert_eq!(kept[0].name, "file-256.txt");
    assert_eq!(kept[MAX_ARTEFACTS - 1].name, "file-001.txt");
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0].name, "file-000.txt");
    assert_eq!(
        excluded[0].reason,
        ExcludedReason::CountLimit {
            limit: MAX_ARTEFACTS
        }
    );
    let line = exclusion_line(&excluded[0]);
    assert!(line.contains("file-000.txt") && line.contains("left out") && line.contains("256"));

    // Synthetic set crossing 1 GiB: 45 files of 25 MiB each (40 fit = 1000 MiB,
    // 41st would reach 1025 MiB > 1024 MiB), plus a tiny older file that must
    // also be left out because everything after the crossing file is excluded.
    let mut big: Vec<Candidate> = (0..45)
        .map(|i| Candidate {
            name: format!("chunk-{i:02}.bin"),
            size: MAX_ARTEFACT_BYTES,
            arrived: 2_000_000_000 + i as u64,
        })
        .collect();
    big.push(Candidate {
        name: "tiny-oldest.txt".into(),
        size: 1,
        arrived: 1_000_000_000,
    });
    let (kept, excluded) = apply_limits(big);
    assert_eq!(kept.len(), 40);
    let expected_used = 40 * MAX_ARTEFACT_BYTES;
    assert!(expected_used <= MAX_ARTEFACT_TOTAL);
    assert_eq!(excluded.len(), 6);
    assert_eq!(excluded[0].name, "chunk-04.bin");
    assert_eq!(excluded[5].name, "tiny-oldest.txt");
    assert_eq!(
        excluded[0].reason,
        ExcludedReason::TotalLimit {
            used: expected_used,
            limit: MAX_ARTEFACT_TOTAL,
        }
    );
    let total_line = exclusion_line(&excluded[0]);
    assert!(
        total_line.contains("chunk-04.bin")
            && total_line.contains("left out")
            && total_line.contains(&expected_used.to_string()),
        "unexpected total exclusion line: {total_line}"
    );
}

#[test]
fn byte_budget_splits_256_long_names_across_frames_with_exact_count() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    std::fs::create_dir_all(&artefacts_dir).unwrap();
    for i in 0..MAX_ARTEFACTS {
        // 120 characters exactly: prefix + 3-digit index + ".txt" = 120 chars.
        let name = format!("{}-{i:03}.txt", "a".repeat(112));
        assert_eq!(name.chars().count(), MAX_ATTACHMENT_NAME_CHARS);
        let path = artefacts_dir.join(&name);
        std::fs::write(&path, b"x").unwrap();
        set_mtime(&path, 1_700_000_000 + i as i64);
    }

    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    device.send(
        "l-big",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let mut got = Vec::new();
    let mut frame_count = 0usize;
    loop {
        let msg = device.receive().expect("artefacts.list frame");
        assert!(fits_device(&msg), "frame exceeded device byte budget");
        match msg {
            ToDevice::ArtefactsList {
                of,
                sandbox,
                count,
                files,
            } => {
                assert_eq!(of.as_str(), "l-big");
                assert_eq!(sandbox, "lab");
                assert_eq!(count, MAX_ARTEFACTS as u32);
                frame_count += 1;
                got.extend(files);
                if got.len() >= count as usize {
                    break;
                }
            }
            other => panic!("expected artefacts.list, got {other:?}"),
        }
    }
    assert_eq!(got.len(), MAX_ARTEFACTS);
    assert!(frame_count >= 1);
    // Verify newest-first order preserved across frames.
    assert!(got[0].name.ends_with("-255.txt"));
    assert!(got[MAX_ARTEFACTS - 1].name.ends_with("-000.txt"));
}

#[test]
fn fetch_serves_chunks_with_whole_file_digest_past_eof_and_resume() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    std::fs::create_dir_all(&artefacts_dir).unwrap();

    // Larger than two ATTACHMENT_CHUNK parts (45,000 * 2 + 1,234).
    let payload: Vec<u8> = (0..(ATTACHMENT_CHUNK * 2 + 1234))
        .map(|i| (i % 251) as u8)
        .collect();
    let expected_digest = encode(&Sha256::digest(&payload));
    std::fs::write(artefacts_dir.join("app.apk"), &payload).unwrap();

    // Plant a leftover copy before bridge start to verify startup sweep.
    let copies_dir = dir.path().join(crate::layout::APP_ARTEFACT_COPIES_DIR);
    std::fs::create_dir_all(&copies_dir).unwrap();
    let stale = copies_dir.join("leftover-copy");
    std::fs::write(&stale, b"stale").unwrap();
    sweep_copies(&copies_dir);
    assert!(
        !stale.exists(),
        "startup sweep should remove leftover copies"
    );

    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    device.send(
        "l-1",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (_, files, _) = receive_list(&mut device, "l-1");
    assert_eq!(files.len(), 1);
    let id = files[0].id.clone();

    // Fetch cumulatively from offset 0.
    let mut assembled = Vec::new();
    let mut offset = 0u64;
    let mut req_idx = 0usize;
    while (offset as usize) < payload.len() {
        req_idx += 1;
        let req_id = format!("g-{req_idx}");
        device.send(
            &req_id,
            FromDevice::ArtefactGet {
                sandbox: "lab".into(),
                artefact: id.clone(),
                offset,
            },
        );
        match device.receive().expect("artefact.data") {
            ToDevice::ArtefactData {
                of,
                artefact,
                offset: got_off,
                size,
                sha256,
                data,
            } => {
                assert_eq!(of.as_str(), req_id);
                assert_eq!(artefact, id);
                assert_eq!(got_off, offset);
                assert_eq!(size, payload.len() as u64);
                assert_eq!(sha256, expected_digest);
                let chunk = decode("data", &data).unwrap();
                assert!(!chunk.is_empty());
                assert!(chunk.len() <= ATTACHMENT_CHUNK);
                assembled.extend_from_slice(&chunk);
                offset += chunk.len() as u64;
            }
            other => panic!("expected artefact.data, got {other:?}"),
        }
    }
    assert_eq!(assembled, payload);

    // Offset past size answers an empty part, not an error.
    device.send(
        "g-eof",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: id.clone(),
            offset: payload.len() as u64 + 100,
        },
    );
    match device.receive().expect("empty artefact.data") {
        ToDevice::ArtefactData {
            of,
            size,
            sha256,
            data,
            ..
        } => {
            assert_eq!(of.as_str(), "g-eof");
            assert_eq!(size, payload.len() as u64);
            assert_eq!(sha256, expected_digest);
            assert!(decode("data", &data).unwrap().is_empty());
        }
        other => panic!("expected empty artefact.data, got {other:?}"),
    }

    // Close first connection; resume on a fresh connection from offset > 0.
    drop(device);
    let (mut resumed, _) = connect(&b, &phone);
    let resume_offset = ATTACHMENT_CHUNK as u64;
    resumed.send(
        "g-resume",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: id.clone(),
            offset: resume_offset,
        },
    );
    match resumed.receive().expect("resumed artefact.data") {
        ToDevice::ArtefactData {
            of,
            offset: got_off,
            size,
            sha256,
            data,
            ..
        } => {
            assert_eq!(of.as_str(), "g-resume");
            assert_eq!(got_off, resume_offset);
            assert_eq!(size, payload.len() as u64);
            assert_eq!(sha256, expected_digest);
            let chunk = decode("data", &data).unwrap();
            assert_eq!(chunk, &payload[ATTACHMENT_CHUNK..ATTACHMENT_CHUNK * 2]);
        }
        other => panic!("expected resumed artefact.data, got {other:?}"),
    }
}

#[test]
fn id_validation_and_unknown_ids_are_refused_without_serving_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    std::fs::create_dir_all(&artefacts_dir).unwrap();
    std::fs::write(artefacts_dir.join("ok.txt"), b"hello").unwrap();

    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    for (i, bad_id) in ["../x", "/etc/passwd", "short", "has space 012345678901"]
        .iter()
        .enumerate()
    {
        let req_id = format!("bad-{i}");
        device.send(
            &req_id,
            FromDevice::ArtefactGet {
                sandbox: "lab".into(),
                artefact: (*bad_id).into(),
                offset: 0,
            },
        );
        match device.receive().expect("error") {
            ToDevice::Error(err) => {
                assert_eq!(
                    err.of.as_ref().map(MessageId::as_str),
                    Some(req_id.as_str())
                );
                assert_eq!(err.code, ErrorCode::BadMessage, "for id {bad_id:?}");
            }
            other => panic!("expected bad_message for {bad_id:?}, got {other:?}"),
        }
    }

    // Empty and over-long sandbox names are bad_message.
    device.send(
        "bad-sb-empty",
        FromDevice::Artefacts {
            sandbox: String::new(),
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::BadMessage),
        other => panic!("expected bad_message, got {other:?}"),
    }
    device.send(
        "bad-sb-long",
        FromDevice::Artefacts {
            sandbox: "s".repeat(129),
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::BadMessage),
        other => panic!("expected bad_message, got {other:?}"),
    }

    // Well-formed 22-char base64url id that matches no file -> not_allowed.
    let missing_id = artefact_id("lab", "does-not-exist.txt");
    device.send(
        "missing-1",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: missing_id,
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => {
            assert_eq!(err.of.as_ref().map(MessageId::as_str), Some("missing-1"));
            assert_eq!(err.code, ErrorCode::NotAllowed);
        }
        other => panic!("expected not_allowed, got {other:?}"),
    }
}

#[test]
fn per_sandbox_ids_are_isolated_and_unserved_sandbox_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (ep_a, dir_a) = sandbox_endpoint(dir.path(), "alpha", "main");
    let (ep_b, dir_b) = sandbox_endpoint(dir.path(), "beta", "main");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::write(dir_a.join("same.txt"), b"from-alpha").unwrap();
    std::fs::write(dir_b.join("same.txt"), b"from-beta").unwrap();

    let b = bridge_for(dir.path(), vec![ep_a, ep_b]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    device.send(
        "la",
        FromDevice::Artefacts {
            sandbox: "alpha".into(),
        },
    );
    let (_, files_a, _) = receive_list(&mut device, "la");
    device.send(
        "lb",
        FromDevice::Artefacts {
            sandbox: "beta".into(),
        },
    );
    let (_, files_b, _) = receive_list(&mut device, "lb");

    assert_eq!(files_a.len(), 1);
    assert_eq!(files_b.len(), 1);
    assert_eq!(files_a[0].name, "same.txt");
    assert_eq!(files_b[0].name, "same.txt");
    assert_ne!(files_a[0].id, files_b[0].id);

    // Using alpha's id under beta is refused.
    device.send(
        "cross",
        FromDevice::ArtefactGet {
            sandbox: "beta".into(),
            artefact: files_a[0].id.clone(),
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::NotAllowed),
        other => panic!("expected not_allowed, got {other:?}"),
    }

    // A sandbox the bridge serves no agent of is refused on both list and get.
    device.send(
        "unserved-l",
        FromDevice::Artefacts {
            sandbox: "ghost".into(),
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::NotAllowed),
        other => panic!("expected not_allowed, got {other:?}"),
    }
    device.send(
        "unserved-g",
        FromDevice::ArtefactGet {
            sandbox: "ghost".into(),
            artefact: files_a[0].id.clone(),
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::NotAllowed),
        other => panic!("expected not_allowed, got {other:?}"),
    }
}

#[test]
fn folder_is_the_truth_when_file_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    std::fs::create_dir_all(&artefacts_dir).unwrap();
    let path = artefacts_dir.join("ephemeral.txt");
    std::fs::write(&path, b"transient").unwrap();

    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    device.send(
        "l-1",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (_, files, _) = receive_list(&mut device, "l-1");
    assert_eq!(files.len(), 1);
    let id = files[0].id.clone();

    // Start fetching part 0 (takes a copy), then remove the file from the folder.
    device.send(
        "g-0",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: id.clone(),
            offset: 0,
        },
    );
    assert!(matches!(
        device.receive(),
        Some(ToDevice::ArtefactData { .. })
    ));

    std::fs::remove_file(&path).unwrap();

    // Next list omits it.
    device.send(
        "l-2",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (count, files, _) = receive_list(&mut device, "l-2");
    assert_eq!(count, 0);
    assert!(files.is_empty());

    // Subsequent fetch of the same id is refused (even though a copy was taken).
    device.send(
        "g-1",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: id,
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::NotAllowed),
        other => panic!("expected not_allowed after removal, got {other:?}"),
    }
}

#[test]
fn capability_is_offered_to_every_person_and_protocol_types_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, _) = sandbox_endpoint(dir.path(), "lab", "main");
    let b = bridge_for(dir.path(), vec![ep]);
    // Host person is victor@example.com; pair a second person (not host's person).
    let guest = paired_as(&b, "n-guest", "guest@example.com");
    *b.whois_login.lock().unwrap() = "guest@example.com".to_owned();
    *b.node.lock().unwrap() = "n-guest".to_owned();
    let (_device, first) = connect_as(&b, &guest, "guest@example.com");
    match first {
        Some(ToDevice::Authenticated { capabilities, .. }) => {
            assert!(
                capabilities.iter().any(|c| c == ARTEFACTS_CAP),
                "expected {ARTEFACTS_CAP} in {capabilities:?}"
            );
        }
        other => panic!("expected authenticated, got {other:?}"),
    }

    // Wire round-trip for FromDevice and ToDevice types and type lists.
    assert!(FROM_DEVICE_TYPES.contains(&"artefacts"));
    assert!(FROM_DEVICE_TYPES.contains(&"artefact.get"));
    assert!(TO_DEVICE_TYPES.contains(&"artefacts.list"));
    assert!(TO_DEVICE_TYPES.contains(&"artefact.data"));

    let list_req = Envelope::new(
        MessageId::new("a-1").unwrap(),
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    assert_eq!(
        decode_from_device(&encode_line(&list_req)).unwrap(),
        list_req
    );

    let get_req = Envelope::new(
        MessageId::new("a-2").unwrap(),
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: "aaaaaaaaaaaaaaaaaaaaaa".into(),
            offset: 45_000,
        },
    );
    assert_eq!(decode_from_device(&encode_line(&get_req)).unwrap(), get_req);

    let list_resp = Envelope::new(
        MessageId::new("a-3").unwrap(),
        ToDevice::ArtefactsList {
            of: MessageId::new("a-1").unwrap(),
            sandbox: "lab".into(),
            count: 1,
            files: vec![Artefact {
                id: "aaaaaaaaaaaaaaaaaaaaaa".into(),
                name: "build.apk".into(),
                mime: "application/vnd.android.package-archive".into(),
                size: 1024,
                arrived: 1_700_000_000,
            }],
        },
    );
    assert_eq!(
        decode_to_device(&encode_line(&list_resp)).unwrap(),
        list_resp
    );

    let data_resp = Envelope::new(
        MessageId::new("a-4").unwrap(),
        ToDevice::ArtefactData {
            of: MessageId::new("a-2").unwrap(),
            artefact: "aaaaaaaaaaaaaaaaaaaaaa".into(),
            offset: 0,
            size: 4,
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            data: encode(b"test"),
        },
    );
    assert_eq!(
        decode_to_device(&encode_line(&data_resp)).unwrap(),
        data_resp
    );
}

#[test]
fn a_file_the_limits_exclude_is_not_served_by_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let (ep, artefacts_dir) = sandbox_endpoint(dir.path(), "lab", "main");
    std::fs::create_dir_all(&artefacts_dir).unwrap();
    // 257 files: the count limit keeps the newest 256.
    for i in 0..=MAX_ARTEFACTS {
        let path = artefacts_dir.join(format!("f-{i:03}.txt"));
        std::fs::write(&path, b"x").unwrap();
        set_mtime(&path, 1_700_000_000 + i as i64);
    }

    let b = bridge_for(dir.path(), vec![ep]);
    let phone = paired(&b, "n-pixel");
    let (mut device, _) = connect(&b, &phone);

    device.send(
        "l-1",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (count, files, _) = receive_list(&mut device, "l-1");
    assert_eq!(count, MAX_ARTEFACTS as u32);
    assert_eq!(files.len(), MAX_ARTEFACTS);
    let oldest = "f-000.txt";
    assert!(files.iter().all(|f| f.name != oldest));

    // The id is well formed and names a file the folder holds, and is
    // still refused: the bridge serves what it lists.
    device.send(
        "g-excluded",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: artefact_id("lab", oldest),
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => assert_eq!(err.code, ErrorCode::NotAllowed),
        other => panic!("expected not_allowed for an excluded file, got {other:?}"),
    }

    // Room appears and the same id is served: the limit is a live sum.
    std::fs::remove_file(artefacts_dir.join("f-256.txt")).unwrap();
    device.send(
        "g-again",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: artefact_id("lab", oldest),
            offset: 0,
        },
    );
    match device.receive().expect("artefact.data") {
        ToDevice::ArtefactData {
            artefact,
            size,
            data,
            ..
        } => {
            assert_eq!(artefact, artefact_id("lab", oldest));
            assert_eq!(size, 1);
            assert_eq!(decode("data", &data).unwrap(), b"x");
        }
        other => panic!("expected artefact.data once room appears, got {other:?}"),
    }
}

/// Pins that the artefacts read path follows `Hub::sees_agent`, not
/// `Hub::serves`: fails if the `sees_agent` filter in `served_sandbox_home`
/// is removed or if `person` stops being threaded through `list`/`get`. This
/// test is the only reader of `Hub::show_to`.
#[test]
fn the_folder_a_person_is_shown_follows_the_audience_rule_not_what_the_bridge_serves() {
    let dir = tempfile::tempdir().unwrap();
    let (ep_lab, dir_lab) = sandbox_endpoint(dir.path(), "lab", "main");
    let (ep_beta, dir_beta) = sandbox_endpoint(dir.path(), "beta", "main");
    std::fs::create_dir_all(&dir_lab).unwrap();
    std::fs::create_dir_all(&dir_beta).unwrap();
    std::fs::write(dir_lab.join("lab.txt"), b"from-lab").unwrap();
    std::fs::write(dir_beta.join("beta.txt"), b"from-beta").unwrap();

    let b = bridge_for(dir.path(), vec![ep_lab, ep_beta]);
    assert!(b.hub.serves("lab/main"));
    assert!(b.hub.serves("beta/main"));
    b.hub.show_to("victor@example.com", ["lab/main"]);
    b.hub.show_to("guest@example.com", ["beta/main"]);
    assert!(b.hub.sees_agent("victor@example.com", "lab/main"));
    assert!(!b.hub.sees_agent("victor@example.com", "beta/main"));
    assert!(!b.hub.sees_agent("guest@example.com", "lab/main"));
    assert!(b.hub.sees_agent("guest@example.com", "beta/main"));

    // Host's person (victor@example.com) sees lab, not beta.
    let phone = paired(&b, "n-pixel");
    let (mut device, first) = connect(&b, &phone);
    assert!(matches!(first, Some(ToDevice::Authenticated { .. })));

    device.send(
        "v-lab-list",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    let (_, lab_files, _) = receive_list(&mut device, "v-lab-list");
    assert_eq!(lab_files.len(), 1);
    assert_eq!(lab_files[0].name, "lab.txt");

    device.send(
        "v-lab-get",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: lab_files[0].id.clone(),
            offset: 0,
        },
    );
    match device.receive().expect("artefact.data") {
        ToDevice::ArtefactData { data, .. } => {
            assert_eq!(decode("data", &data).unwrap(), b"from-lab");
        }
        other => panic!("expected artefact.data for lab, got {other:?}"),
    }

    device.send(
        "v-beta-list",
        FromDevice::Artefacts {
            sandbox: "beta".into(),
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => {
            assert_eq!(err.code, ErrorCode::NotAllowed);
            assert_eq!(err.message, "no such artefact");
        }
        other => panic!("expected not_allowed for beta list, got {other:?}"),
    }

    device.send(
        "v-beta-get",
        FromDevice::ArtefactGet {
            sandbox: "beta".into(),
            artefact: artefact_id("beta", "beta.txt"),
            offset: 0,
        },
    );
    match device.receive().expect("error") {
        ToDevice::Error(err) => {
            assert_eq!(err.code, ErrorCode::NotAllowed);
            assert_eq!(err.message, "no such artefact");
        }
        other => panic!("expected not_allowed for beta get, got {other:?}"),
    }

    // Second person (guest@example.com) sees beta, not lab.
    *b.whois_login.lock().unwrap() = "guest@example.com".to_owned();
    *b.node.lock().unwrap() = "n-guest".to_owned();
    let guest = paired_as(&b, "n-guest", "guest@example.com");
    let (mut guest_device, first) = connect_as(&b, &guest, "guest@example.com");
    assert!(matches!(first, Some(ToDevice::Authenticated { .. })));

    guest_device.send(
        "g-beta-list",
        FromDevice::Artefacts {
            sandbox: "beta".into(),
        },
    );
    let (_, beta_files, _) = receive_list(&mut guest_device, "g-beta-list");
    assert_eq!(beta_files.len(), 1);
    assert_eq!(beta_files[0].name, "beta.txt");

    guest_device.send(
        "g-beta-get",
        FromDevice::ArtefactGet {
            sandbox: "beta".into(),
            artefact: beta_files[0].id.clone(),
            offset: 0,
        },
    );
    match guest_device.receive().expect("artefact.data") {
        ToDevice::ArtefactData { data, .. } => {
            assert_eq!(decode("data", &data).unwrap(), b"from-beta");
        }
        other => panic!("expected artefact.data for beta, got {other:?}"),
    }

    guest_device.send(
        "g-lab-list",
        FromDevice::Artefacts {
            sandbox: "lab".into(),
        },
    );
    match guest_device.receive().expect("error") {
        ToDevice::Error(err) => {
            assert_eq!(err.code, ErrorCode::NotAllowed);
            assert_eq!(err.message, "no such artefact");
        }
        other => panic!("expected not_allowed for lab list, got {other:?}"),
    }

    guest_device.send(
        "g-lab-get",
        FromDevice::ArtefactGet {
            sandbox: "lab".into(),
            artefact: artefact_id("lab", "lab.txt"),
            offset: 0,
        },
    );
    match guest_device.receive().expect("error") {
        ToDevice::Error(err) => {
            assert_eq!(err.code, ErrorCode::NotAllowed);
            assert_eq!(err.message, "no such artefact");
        }
        other => panic!("expected not_allowed for lab get, got {other:?}"),
    }
}
