//! Running a store's command-line tool: nothing here may ask anything, so
//! every call ends after a set wait.

use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

/// How long a call to a store's tool may take: long past any answer, short
/// of a wait on a dialog nobody sees.
pub(super) const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// Runs `command` with `input` on its standard input, ending it after
/// [`ANSWER_WAIT`]: past that, it waits on something nobody will answer.
pub(super) fn run(command: &mut Command, input: Option<&[u8]>) -> Result<Output, String> {
    run_for(command, input, ANSWER_WAIT)
}

pub(super) fn run_for(
    command: &mut Command,
    input: Option<&[u8]>,
    wait: Duration,
) -> Result<Output, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdin(match input {
            Some(_) => Stdio::piped(),
            None => Stdio::null(),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    // Read as it writes, so a long answer never fills a pipe and stalls it.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                pipe.read_to_end(&mut bytes)?;
            }
            Ok::<_, io::Error>(bytes)
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
    let status = wait_for(&mut child, &program, input, wait);
    if status.is_err() {
        // The child this call started, and nothing else.
        let _ = child.kill();
        let _ = child.wait();
    }
    let joined = |drain: std::thread::JoinHandle<io::Result<Vec<u8>>>| match drain.join() {
        Ok(read) => read.map_err(|e| format!("cannot read what {program} answered: {e}")),
        Err(_) => Err(format!("lost what {program} answered")),
    };
    let (stdout, stderr) = (joined(stdout), joined(stderr));
    // Why it failed, as the tool said it, when it said anything.
    let status = status.map_err(|e| match &stderr {
        Ok(said) if !said.is_empty() => {
            format!("{e} ({})", scrub(String::from_utf8_lossy(said).trim(), ""))
        }
        _ => e,
    })?;
    Ok(Output {
        status,
        stdout: stdout?,
        stderr: stderr?,
    })
}

/// Gives `child` its input, which it reads before anything it could wait
/// on, and waits for it to end, for at most `wait`. A child that closed its
/// input first did not want it: how it exits is the answer, as when it
/// refuses before reading, so a closed pipe is no failure here.
fn wait_for(
    child: &mut Child,
    program: &str,
    input: Option<&[u8]>,
    wait: Duration,
) -> Result<ExitStatus, String> {
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("piped");
        match stdin.write_all(input) {
            Err(e) if e.kind() != io::ErrorKind::BrokenPipe => {
                return Err(format!("cannot give {program} its input: {e}"));
            }
            _ => {}
        }
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < wait => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                return Err(format!(
                    "{program} did not answer within {} seconds, as if it waited on a dialog; it was ended",
                    wait.as_secs()
                ));
            }
            Err(e) => return Err(format!("lost {program}: {e}")),
        }
    }
}

pub(super) fn stderr(bytes: &[u8], status: ExitStatus) -> String {
    match String::from_utf8_lossy(bytes).trim() {
        "" if status.success() => String::new(),
        "" => status.to_string(),
        why => why.to_owned(),
    }
}

/// `text` with every run of hex digits that could be part of a value left
/// out: one of 16 or more digits, and one of 4 or more found in `value`,
/// the hex-encoded value.
pub(super) fn scrub(text: &str, value: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        let lower = run.to_ascii_lowercase();
        let of_value =
            !run.is_empty() && (lower == value || (run.len() >= 4 && value.contains(&lower)));
        match run.len() >= 16 || of_value {
            true => out.push('…'),
            false => out.push_str(&run),
        }
        run.clear();
        out.push(c);
    }
    out.pop();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// More than any pipe holds, so writing it to a tool that never reads
    /// meets a closed pipe however fast the tool exits.
    fn past_a_pipe() -> Vec<u8> {
        vec![b'k'; 4 << 20]
    }

    /// A tool that exits before reading its input refused it: what it said
    /// and how it exited are the answer, not the pipe it left closed.
    #[test]
    fn a_tool_that_exits_before_reading_its_input_answers_with_its_exit() {
        let input = past_a_pipe();
        let out = run(
            Command::new("/bin/sh").args(["-c", "echo 'it is locked' >&2; exit 1"]),
            Some(&input),
        )
        .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(stderr(&out.stderr, out.status), "it is locked");
    }

    /// Exiting 0 without reading is still told as it is: a caller that
    /// needs its input taken checks for it, as a store reads its value back.
    #[test]
    fn a_tool_that_exits_0_before_reading_its_input_answers_with_its_exit() {
        let input = past_a_pipe();
        let out = run(Command::new("/bin/sh").args(["-c", "exit 0"]), Some(&input)).unwrap();
        assert!(out.status.success());
    }
}
