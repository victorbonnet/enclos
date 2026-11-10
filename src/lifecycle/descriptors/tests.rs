use super::*;

fn me() -> u32 {
    std::process::id()
}

#[test]
fn every_process_is_listed_with_what_it_holds_and_other_entries_are_not() {
    let proc = tempfile::tempdir().unwrap();
    fake_process(proc.path(), me(), &[]);
    fake_process(proc.path(), 7, &["/a", "socket:[12]"]);
    // Listed, but exited before its descriptors were read.
    std::fs::create_dir(proc.path().join("8")).unwrap();
    std::fs::create_dir(proc.path().join("sys")).unwrap();
    let found = every_process(proc.path()).unwrap();
    let held = found.iter().find(|(pid, _)| *pid == 7).unwrap();
    assert_eq!(held.1.len(), 2, "{found:?}");
    assert!(
        held.1.iter().any(|d| d.target == Path::new("socket:[12]")),
        "{found:?}"
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn a_listing_that_does_not_show_the_caller_is_an_error() {
    let proc = tempfile::tempdir().unwrap();
    fake_process(proc.path(), me().wrapping_add(1), &[]);
    let err = every_process(proc.path()).unwrap_err();
    assert!(err.to_string().contains("the caller"), "{err}");
    assert!(every_process(&proc.path().join("none")).is_err());
}

/// On a `/proc` mounted with `hidepid=1`, another user's folder is listed
/// and nothing in it can be read, its threads neither: that process is
/// unreadable and left out of the listing, while the caller's is read.
#[test]
fn a_process_whose_whole_folder_is_refused_is_unreadable_and_left_out() {
    let proc = tempfile::tempdir().unwrap();
    fake_process(proc.path(), me(), &["/mine"]);
    fake_process(proc.path(), 7, &["/theirs"]);
    fake_process(&proc.path().join("7/task"), 8, &["/theirs"]);
    let folder = refuse(&proc.path().join("7"));
    let one = of(proc.path(), 7);
    let every = every_process(proc.path());
    folder.restore();
    assert_eq!(one.unwrap(), Descriptors::Unreadable);
    let every = every.unwrap();
    assert_eq!(every.len(), 1, "{every:?}");
    assert_eq!(every[0].0, me());
}

/// The caller refused the same way leaves a listing that cannot be trusted.
#[test]
fn a_listing_whose_caller_is_refused_is_an_error() {
    let proc = tempfile::tempdir().unwrap();
    fake_process(proc.path(), me(), &[]);
    fake_process(proc.path(), 7, &[]);
    let folder = refuse(&proc.path().join(me().to_string()));
    let every = every_process(proc.path());
    folder.restore();
    let err = every.unwrap_err();
    assert!(err.to_string().contains("the caller"), "{err}");
}

/// A process whose main thread exited: its own folder is root's, and
/// the thread left on it reads what they all hold.
#[test]
fn a_process_is_read_through_a_thread_when_its_own_folder_is_refused() {
    let proc = tempfile::tempdir().unwrap();
    let task = proc.path().join("7/task");
    fake_process(proc.path(), 7, &[]);
    fake_process(&task, 7, &[]);
    fake_process(&task, 8, &["/a"]);
    std::fs::remove_dir(task.join("7/fd")).unwrap();
    let fd = refuse(&proc.path().join("7/fd"));
    let read = of(proc.path(), 7);
    fd.restore();
    let Descriptors::Open(open) = read.unwrap() else {
        panic!("the thread was not read");
    };
    assert_eq!(open[0].target, Path::new("/a"));
    assert!(open[0].opens().unwrap());
}

/// With no other thread, or none that reads, it stays unreadable.
#[test]
fn a_process_no_thread_of_which_reads_is_unreadable() {
    let proc = tempfile::tempdir().unwrap();
    let task = proc.path().join("7/task");
    fake_process(proc.path(), 7, &[]);
    fake_process(&task, 7, &[]);
    let fd = refuse(&proc.path().join("7/fd"));
    assert_eq!(of(proc.path(), 7).unwrap(), Descriptors::Unreadable);
    fake_process(&task, 8, &[]);
    let thread = refuse(&task.join("8/fd"));
    let read = of(proc.path(), 7);
    fd.restore();
    thread.restore();
    assert_eq!(read.unwrap(), Descriptors::Unreadable);
}

/// `fdinfo`'s flags say what a descriptor opens, and one that shows none
/// is a look that failed.
#[test]
fn a_descriptor_opens_its_target_unless_it_is_o_path_or_closed() {
    let proc = tempfile::tempdir().unwrap();
    fake_process(proc.path(), 7, &["/a", "/b", "/c", "/d"]);
    let info = proc.path().join("7/fdinfo");
    fake_flags(&info.join("1"), "012000000");
    std::fs::remove_file(info.join("2")).unwrap();
    std::fs::write(info.join("3"), "pos:\t0\n").unwrap();
    let Descriptors::Open(mut open) = of(proc.path(), 7).unwrap() else {
        panic!("the process cannot be read");
    };
    open.sort_by(|a, b| a.target.cmp(&b.target));
    assert!(open[0].opens().unwrap());
    assert!(!open[1].opens().unwrap());
    assert!(!open[2].opens().unwrap());
    assert!(open[3].opens().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn o_path_is_the_kernels() {
    assert_eq!(O_PATH, rustix::fs::OFlags::PATH.bits());
}

/// A descriptor on a folder deeper than `/proc` can write, past any page
/// a kernel may use: one such descriptor anywhere must not fail the look
/// at every process.
#[cfg(target_os = "linux")]
#[test]
fn a_descriptor_too_deep_to_name_is_left_out() {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let name = "d".repeat(255);
    let read = OFlags::RDONLY | OFlags::DIRECTORY;
    let mut deep = open(dir.path(), read, Mode::empty()).unwrap();
    for _ in 0..300 {
        mkdirat(&deep, &name, Mode::RWXU).unwrap();
        deep = openat(&deep, &name, read, Mode::empty()).unwrap();
    }
    let proc = Path::new(PROC);
    let link = proc.join("self/fd").join(deep.as_raw_fd().to_string());
    let err = std::fs::read_link(&link).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(rustix::io::Errno::NAMETOOLONG.raw_os_error())
    );
    let found = every_process(proc).unwrap();
    assert!(found.iter().any(|(pid, _)| *pid == me()));
}

#[cfg(target_os = "linux")]
#[test]
fn a_zombie_is_unreadable_and_a_reaped_process_is_gone() {
    let proc = Path::new(PROC);
    let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let pid = child.id();
    let start = std::time::Instant::now();
    while of(proc, pid).unwrap() != Descriptors::Unreadable {
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.wait().unwrap();
    assert_eq!(of(proc, pid).unwrap(), Descriptors::Gone);
}
