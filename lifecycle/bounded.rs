//! A host command run to its end, or ended at a limit: what enclos asks
//! `ps` and `lsof` while it holds the state lock must not hold it for long.

use std::io::{self, Read};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long one `ps` or `lsof` may take: they answer in a fraction of a
/// second (`lsof -d txt` of every process in 0.12 s on macOS 26.5.2), so
/// this is reached only by one that hangs.
pub const LIMIT: Duration = Duration::from_secs(5);

/// `command`'s output, its input closed; past `limit`, it is sent KILL (it
/// is this process's own child), reaped apart, and the error says it did
/// not answer.
pub fn output_within(command: &mut Command, limit: Duration) -> io::Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Read as it writes, so a long answer never fills a pipe and stalls it.
    // Each reader says when its pipe ends, as it does when the command
    // exits: its answer is taken then, not at the next look.
    let (ended, pipe_ended) = mpsc::channel();
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        let ended = ended.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let read = match pipe {
                Some(mut pipe) => pipe.read_to_end(&mut bytes).map(|_| bytes),
                None => Ok(bytes),
            };
            let _ = ended.send(());
            read
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + limit;
    let left = || deadline.saturating_duration_since(Instant::now());
    let mut piped = 2;
    let status = loop {
        if piped > 0 {
            if pipe_ended.recv_timeout(left()).is_ok() {
                piped -= 1;
                continue;
            }
        } else if let Some(status) = child.try_wait()? {
            break status;
        }
        if left().is_zero() {
            // Not waited for here: one stuck in a call that does not end on
            // KILL (a network mount) would hold the caller with it.
            let _ = child.kill();
            std::thread::spawn(move || child.wait());
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("did not answer within {} s", limit.as_secs()),
            ));
        }
        // Both pipes ended: the command is exiting, if it has not.
        if piped == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let joined = |t: std::thread::JoinHandle<io::Result<Vec<u8>>>| {
        t.join()
            .unwrap_or_else(|_| Err(io::Error::other("its output could not be read")))
    };
    Ok(Output {
        status,
        stdout: joined(stdout)?,
        stderr: joined(stderr)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_that_answers_gives_its_output_and_one_that_hangs_is_ended() {
        let out = output_within(Command::new("/bin/echo").arg("hi"), LIMIT).unwrap();
        assert_eq!(out.stdout, b"hi\n");
        let started = Instant::now();
        let err = output_within(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
