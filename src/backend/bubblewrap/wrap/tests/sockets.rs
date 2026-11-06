//! The host's listening sockets under the user's home, masked at each
//! launch: which are, from a `/proc/net/unix` table, and where their masks
//! go among bubblewrap's arguments.

use super::*;
use crate::backend::bubblewrap::sockets::paths_in;

/// A `/proc/net/unix` table with a listening stream socket at each path.
fn table(paths: &[PathBuf]) -> String {
    let mut table = "Num       RefCount Protocol Flags    Type St Inode Path\n".to_owned();
    for (inode, path) in paths.iter().enumerate() {
        table.push_str(&format!(
            "0000000000000000: 00000002 00000000 00010000 0001 01 {inode:>8} {}\n",
            path.display()
        ));
    }
    table
}

/// Only a socket under the home that the sandbox would see is masked: not
/// one in the sandbox's home or a workspace, which are its own, nor one
/// under a deny entry or enclos's folder, hidden already, nor one outside
/// the home, nor one gone since the table was read.
#[test]
fn a_socket_under_the_home_that_the_sandbox_would_see_is_masked() {
    let home = Home::new();
    let elsewhere = tempfile::tempdir().unwrap();
    let other_install = home.file("enclos-wal/run/w1/visible/proxy.sock");
    let in_sandbox_home = home.file(".enclos/sandboxes/lab/home/.hermes/gateway.sock");
    let in_workspace = home.file("proj/dev.sock");
    let denied = home.file(".ssh/agent.sock");
    let own_proxy = home.file(".enclos/run/lab/visible/proxy.sock");
    let outside = elsewhere.path().join("x.sock");
    std::fs::write(&outside, "").unwrap();
    let gone = home.at("left/gone.sock");
    let listed = [
        other_install.clone(),
        in_sandbox_home,
        in_workspace,
        denied,
        own_proxy,
        outside,
        gone,
    ];
    let c = compiled(
        &home,
        Lists {
            denied: vec![home.at(".ssh")],
            workspaces: vec![home.folder("proj")],
            ..Lists::default()
        },
    );
    let host = read_host(&c, &home.sandbox_home(), None, &paths_in(&table(&listed))).unwrap();
    assert_eq!(host.sockets, [other_install]);
}

/// Each is masked as a file is, by bubblewrap's `/dev/null`, after the
/// home's mask binds back the folder that holds it, and before the
/// compiled mounts.
#[test]
fn a_socket_is_masked_after_the_homes_mask_and_before_the_mounts() {
    let home = Home::new();
    let socket = home.file("enclos-wal/run/w1/visible/proxy.sock");
    let c = compiled(&home, Lists::default());
    let host = read_host(
        &c,
        &home.sandbox_home(),
        None,
        std::slice::from_ref(&socket),
    )
    .unwrap();
    let args = strings(&arguments(&c, &host, &[]));
    let mask = position(&args, &["--ro-bind", "/dev/null", &text(&socket)]);
    let homes = position(&args, &["--tmpfs", &text(&home.user())]);
    let wal = home.at("enclos-wal");
    let bound_back = position(&args, &["--ro-bind-try", &text(&wal), &text(&wal)]);
    let mounts = position(
        &args,
        &[
            "--bind",
            &text(&home.sandbox_home()),
            &text(&home.sandbox_home()),
        ],
    );
    assert!(
        homes < bound_back && bound_back < mask && mask < mounts,
        "{args:?}"
    );
}
