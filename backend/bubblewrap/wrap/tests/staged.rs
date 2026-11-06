//! The files an install or an import reads from the sandbox's `installers/` folder.

use super::*;

/// The data folder is hidden from the sandbox, so what an install reads
/// there is bound back, each file alone and read-only, after the binds the
/// compiled file makes and before anything is sealed.
#[test]
fn the_files_an_install_staged_are_bound_read_only_and_nothing_else_of_their_folder() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let reads = staged(&home);
    let args = strings(&arguments(&c, &host, &reads));
    let sandbox = text(&home.sandbox_home());
    let bound = position(&args, &["--bind", &sandbox, &sandbox]);
    let first_seal = args.iter().position(|a| a == "--remount-ro").unwrap();
    for file in &reads {
        let at = position(&args, &["--ro-bind", &text(file), &text(file)]);
        assert!(bound < at && at < first_seal, "{args:?}");
    }
    let installers = text(&ctx(&home).installers);
    let shown: Vec<&String> = args.iter().filter(|a| a.contains(&installers)).collect();
    assert_eq!(shown.len(), 2 * reads.len(), "{args:?}");
    assert!(!args.contains(&installers), "{args:?}");
}

/// A session that reads nothing staged sees none of the folder.
#[test]
fn a_session_that_reads_nothing_staged_is_shown_nothing_of_the_installers() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let file = Path::new("/c/compiled/x.json");
    let command = command(&programs, file, &c, &host, &ctx(&home), &launch(Vec::new())).unwrap();
    let installers = text(&ctx(&home).installers);
    let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
    assert!(!args.iter().any(|a| a.contains(&installers)), "{args:?}");
}

/// A data folder outside the user's home is a tmpfs of its own: sealed
/// before the staged files are bound, bubblewrap could not make their
/// mount points in it.
#[test]
fn a_protected_folder_outside_the_home_is_sealed_after_the_staged_files() {
    let home = Home::new();
    let elsewhere = home.folder("srv/enclos");
    let c = compiled(
        &home,
        Lists {
            sealed: vec![elsewhere.clone()],
            ..Lists::default()
        },
    );
    let host = read(&home, &c, None).unwrap();
    let reads = staged(&home);
    let args = strings(&arguments(&c, &host, &reads));
    let sealed = position(&args, &["--remount-ro", &text(&elsewhere)]);
    for file in &reads {
        assert!(position(&args, &["--ro-bind", &text(file), &text(file)]) < sealed);
    }
    // Sealed last, with only the options, whose place does not matter, after.
    let options = c.bubblewrap.options.len();
    assert_eq!(args.len(), sealed + 2 + options, "sealed last: {args:?}");
}

/// Only a file of the sandbox's own `installers/` folder is bound: not the
/// folder, nothing below a folder in it, and nothing elsewhere.
#[test]
fn only_a_file_of_the_sandboxs_installers_folder_is_shown() {
    let installers = Path::new("/d/sandboxes/lab/installers");
    assert!(staged_only(installers, &[installers.join("home-0")]).is_ok());
    assert!(staged_only(installers, &[]).is_ok());
    for refused in [
        installers.to_path_buf(),
        installers.join("deep/home-0"),
        installers.join(".."),
        PathBuf::from("/d/sandboxes/other/installers/home-0"),
        PathBuf::from("/d/state.db"),
        PathBuf::from("home-0"),
    ] {
        let why = staged_only(installers, &[installers.join("home-0"), refused.clone()])
            .unwrap_err()
            .to_string();
        assert!(why.contains(&refused.display().to_string()), "{why}");
    }
}

/// A launch naming another file starts nothing.
#[test]
fn a_launch_reading_a_file_enclos_did_not_stage_is_refused() {
    let home = Home::new();
    let c = compiled(&home, Lists::default());
    let host = read(&home, &c, None).unwrap();
    let programs = Programs {
        bwrap: Path::new("/usr/bin/bwrap"),
        enclos: Path::new("/usr/bin/enclos"),
    };
    let mut launch = launch(Vec::new());
    launch.reads = vec![home.at(".enclos/state.db")];
    let file = Path::new("/c/compiled/x.json");
    let why = command(&programs, file, &c, &host, &ctx(&home), &launch)
        .unwrap_err()
        .to_string();
    assert!(why.contains("is not a file enclos stages"), "{why}");
}
