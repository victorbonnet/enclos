//! The files each process maps, from `/proc/<pid>/exe` and
//! `/proc/<pid>/maps`: its executable, the libraries it loaded and any other
//! file it maps. How Linux answers what `lsof -d txt` does on macOS.
//!
//! Each name is the path as this process's root sees it, written as `maps`
//! writes it; [`program_name`] writes a path the same way. Only the user's
//! own processes can be read, and among them not one that is not dumpable,
//! as with their descriptors (`descriptors`).

use std::collections::BTreeMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::super::descriptors::is_gone;
use super::super::programs::ProgramsError;

/// `path` as `maps` writes a file's name: a newline as `\012`, every other
/// byte as it is, read as UTF-8 with what does not read as such replaced.
/// So two names can read the same, a path holding `\012` and one holding a
/// newline say: matched this way, such a name may be taken for another,
/// never missed.
pub fn program_name(path: &Path) -> String {
    String::from_utf8_lossy(path.as_os_str().as_bytes()).replace('\n', "\\012")
}

/// What reading one of a process's files found.
enum Read<T> {
    Found(T),
    /// The process is gone, or has no such file, as a kernel thread has no
    /// executable.
    Missing,
    /// The process cannot be read by this user.
    Refused,
}

fn read<T>(result: io::Result<T>) -> io::Result<Read<T>> {
    match result {
        Ok(found) => Ok(Read::Found(found)),
        Err(e) if is_gone(&e) => Ok(Read::Missing),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(Read::Refused),
        Err(e) => Err(e),
    }
}

/// The file names in a `maps`: the sixth field of each line, after padding,
/// when it is a path. Others are `[heap]`, `[stack]`, `[vdso]` and the like,
/// or nothing for an anonymous mapping. A file removed since it was mapped
/// keeps its path, followed by ` (deleted)`.
fn mapped(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let mut rest = line;
        for _ in 0..5 {
            rest = rest.trim_start().split_once(' ')?.1;
        }
        let name = rest.trim_start();
        name.starts_with('/').then_some(name)
    })
}

/// The executable and mapped files of `pid`, under `proc`, each once, or
/// `None` when it cannot be read or is gone.
fn files_of(proc: &Path, pid: u32) -> io::Result<Option<Vec<String>>> {
    let folder = proc.join(pid.to_string());
    let mut files = Vec::new();
    match read(std::fs::read_link(folder.join("exe")))? {
        Read::Found(exe) => files.push(program_name(&exe)),
        Read::Missing => {}
        Read::Refused => return Ok(None),
    }
    let maps = match read(std::fs::read(folder.join("maps")))? {
        Read::Found(maps) => maps,
        Read::Missing | Read::Refused => return Ok(None),
    };
    for name in mapped(&String::from_utf8_lossy(&maps)) {
        if !files.iter().any(|f| f == name) {
            files.push(name.to_owned());
        }
    }
    Ok(Some(files))
}

/// The program files of every process under `proc` this user can read, by
/// pid. A listing without this process, whose program is mapped, cannot be
/// the whole listing.
pub(super) fn program_files_under(
    proc: &Path,
) -> Result<BTreeMap<u32, Vec<String>>, ProgramsError> {
    let error = |e: io::Error| ProgramsError::proc(format!("{}: {e}", proc.display()));
    let mut found = BTreeMap::new();
    for entry in std::fs::read_dir(proc).map_err(error)? {
        let Some(pid) = entry
            .map_err(error)?
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(files) = files_of(proc, pid).map_err(error)? {
            found.insert(pid, files);
        }
    }
    let me = std::process::id();
    match found.get(&me) {
        Some(files) if !files.is_empty() => Ok(found),
        _ => Err(ProgramsError::proc(format!(
            "{} shows no program file of pid {me}, the caller",
            proc.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    const MAPS: &str = "\
55d0c0a00000-55d0c0a28000 r--p 00000000 103:02 1311491                   /usr/bin/python3.12
55d0c0a28000-55d0c0d3c000 r-xp 00028000 103:02 1311491                   /usr/bin/python3.12
55d0c2f1e000-55d0c3083000 rw-p 00000000 00:00 0                          [heap]
7f2a5c000000-7f2a5c021000 rw-p 00000000 00:00 0
7f2a60a00000-7f2a60a30000 r--p 00000000 103:02 2490368                   /home/a/s b/lib.so (deleted)
7ffd5a9e7000-7ffd5aa08000 rw-p 00000000 00:00 0                          [stack]
";

    fn fake(proc: &Path, pid: u32, exe: Option<&str>, maps: &str) {
        let dir = proc.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(exe) = exe {
            std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
        }
        std::fs::write(dir.join("maps"), maps).unwrap();
    }

    #[test]
    fn only_the_paths_a_process_maps_are_its_files() {
        let names: Vec<&str> = mapped(MAPS).collect();
        assert_eq!(
            names,
            [
                "/usr/bin/python3.12",
                "/usr/bin/python3.12",
                "/home/a/s b/lib.so (deleted)"
            ]
        );
    }

    #[test]
    fn a_path_is_named_as_maps_writes_it() {
        let odd = Path::new(std::ffi::OsStr::from_bytes(b"/s/a\nb \\ \xff/x"));
        assert_eq!(program_name(odd), "/s/a\\012b \\ \u{fffd}/x");
    }

    /// Each process's executable and mapped files, each once; a kernel
    /// thread, which has no executable, maps none; one gone has none.
    #[test]
    fn each_process_gets_its_executable_and_mapped_files() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        let me = std::process::id();
        fake(proc, me, Some("/usr/bin/enclos"), "");
        fake(proc, 7, Some("/usr/bin/python3.12"), MAPS);
        fake(proc, 2, None, "");
        std::fs::create_dir_all(proc.join("9")).unwrap();
        let found = program_files_under(proc).unwrap();
        assert_eq!(found[&me], ["/usr/bin/enclos"]);
        assert_eq!(
            found[&7],
            ["/usr/bin/python3.12", "/home/a/s b/lib.so (deleted)"]
        );
        assert!(found[&2].is_empty());
        assert!(!found.contains_key(&9));
    }

    #[test]
    fn a_listing_without_the_caller_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path();
        fake(proc, 7, Some("/usr/bin/python3.12"), MAPS);
        let err = program_files_under(proc).unwrap_err().to_string();
        assert!(
            err.starts_with("cannot look at the programs processes run with /proc:"),
            "{err}"
        );
        assert!(err.contains("shows no program file of pid"), "{err}");
    }

    /// On this host, this process's own program is listed, by its real
    /// path, as `program_name` writes it.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_listed_with_its_program() {
        let found = program_files_under(Path::new(super::super::super::descriptors::PROC)).unwrap();
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mine = &found[&std::process::id()];
        assert!(
            mine.contains(&program_name(&exe)),
            "{exe:?} not in {mine:?}"
        );
    }

    /// A data file a process maps, in a folder whose name holds a newline
    /// and a space, is listed as `program_name` writes its path.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mapped_data_file_is_listed_by_its_path() {
        use std::io::BufRead;
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join("a\nb c");
        std::fs::create_dir(&odd).unwrap();
        let data = odd.join("data");
        std::fs::write(&data, b"mapped").unwrap();
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import mmap, sys, time\n\
                 f = open(sys.argv[1], 'rb')\n\
                 m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)\n\
                 print('mapped', flush=True)\n\
                 time.sleep(30)\n",
            ])
            .arg(&data)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let found = program_files_under(Path::new(super::super::super::descriptors::PROC));
        let _ = child.kill();
        let _ = child.wait();
        let files = &found.unwrap()[&child.id()];
        let name = program_name(&std::fs::canonicalize(&data).unwrap());
        assert!(name.contains("a\\012b c"), "{name}");
        assert!(files.contains(&name), "{name} not in {files:?}");
    }
}
