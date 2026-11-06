//! LOOP (to drop): does a test's own `sleep`, started with a plain
//! `Command::spawn` while another thread starts marked programs and stops
//! their holders, get stopped with them? And with `spawn_unmarked`?

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::marker::{Marker, holders, spawn_unmarked};
use super::process::{is_same, reference};

/// Another test: starts a marked program, then stops every holder of its
/// marker, as `sandbox stop` does, again and again.
fn stopping_sessions(
    done: Arc<AtomicBool>,
    killed: Arc<AtomicUsize>,
) -> std::thread::JoinHandle<()> {
    let dir = tempfile::tempdir().unwrap();
    std::thread::spawn(move || {
        let members = dir.path().canonicalize().unwrap().join("members");
        while !done.load(Ordering::Relaxed) {
            let marker = Marker::new(&members).unwrap();
            let mut command = Command::new("/bin/sleep");
            command.arg("5");
            let (mut child, started) = marker.spawn(&mut command).unwrap();
            let root = reference(child.id()).unwrap().unwrap();
            started.name(&root).unwrap();
            for pids in holders(&members).unwrap().values() {
                for pid in pids {
                    if *pid != child.id() {
                        killed.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = Command::new("/bin/kill")
                        .args(["-9", &pid.to_string()])
                        .status();
                }
            }
            let _ = child.kill();
            child.wait().unwrap();
            super::marker::remove(&members, &root).unwrap();
        }
    })
}

fn survivors(unmarked: bool, tries: usize) -> (usize, usize) {
    let done = Arc::new(AtomicBool::new(false));
    let killed = Arc::new(AtomicUsize::new(0));
    let other = stopping_sessions(done.clone(), killed.clone());
    let mut lost = 0;
    for _ in 0..tries {
        let mut children: Vec<_> = (0..50)
            .map(|_| {
                let mut command = Command::new("/bin/sleep");
                command.arg("30");
                let child = if unmarked {
                    spawn_unmarked(&mut command).unwrap()
                } else {
                    command.spawn().unwrap()
                };
                let mine = reference(child.id()).unwrap().unwrap();
                (child, mine)
            })
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        for (child, mine) in &mut children {
            if !is_same(mine).unwrap() {
                lost += 1;
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    done.store(true, Ordering::Relaxed);
    other.join().unwrap();
    (lost, killed.load(Ordering::Relaxed))
}

#[test]
#[ignore = "LOOP (to drop): run by the loop step"]
fn scratch_plain_spawn_is_stopped_with_another_tests_session() {
    let tries = std::env::var("TRIES")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(60);
    let (lost, killed) = survivors(false, tries);
    eprintln!(
        "plain spawn: {lost} of {} sleeps stopped by the other session ({killed} foreign holders killed)",
        tries * 50
    );
    let (lost, killed) = survivors(true, tries);
    eprintln!(
        "spawn_unmarked: {lost} of {} sleeps stopped by the other session ({killed} foreign holders killed)",
        tries * 50
    );
}
