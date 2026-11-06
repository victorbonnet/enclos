//! Which cgroup controllers reach the user's systemd manager, which a
//! session's scope can be held by (design §5, Degraded controls on Linux).
//! A controller must be in the kernel's root cgroup and delegated to the
//! user's manager, `user@<uid>.service`, whose cgroup lists what it was
//! given.

use std::path::Path;

/// Why `memory` is not held on the hierarchy at `root` for user `uid`, or
/// none when it is: the memory controller missing from the kernel's root
/// cgroup, or not delegated to the user's manager, or either list unread.
pub fn memory_not_held(root: &Path, uid: u32) -> Option<String> {
    let at_root = root.join("cgroup.controllers");
    let manager = root
        .join("user.slice")
        .join(format!("user-{uid}.slice"))
        .join(format!("user@{uid}.service"))
        .join("cgroup.controllers");
    let lists = |file: &Path| -> Result<bool, String> {
        std::fs::read_to_string(file)
            .map(|text| text.split_whitespace().any(|c| c == "memory"))
            .map_err(|e| format!("cannot read {}: {e}", file.display()))
    };
    match lists(&at_root) {
        Err(why) => return Some(why),
        Ok(false) => {
            return Some(format!(
                "this host's kernel has no memory controller (`memory` is not in {})",
                at_root.display()
            ));
        }
        Ok(true) => {}
    }
    match lists(&manager) {
        Err(why) => Some(why),
        Ok(false) => Some(format!(
            "the memory controller is not delegated to the user's systemd manager (`memory` is not in {})",
            manager.display()
        )),
        Ok(true) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in hierarchy whose root lists `root` and whose user 1000's
    /// manager lists `manager`, if given.
    fn hierarchy(root: &str, manager: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.controllers"), root).unwrap();
        if let Some(manager) = manager {
            let folder = dir
                .path()
                .join("user.slice/user-1000.slice/user@1000.service");
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("cgroup.controllers"), manager).unwrap();
        }
        dir
    }

    #[test]
    fn memory_delegated_to_the_users_manager_is_held() {
        let ubuntu = hierarchy(
            "cpuset cpu io memory hugetlb pids rdma misc\n",
            Some("cpu memory pids\n"),
        );
        assert_eq!(memory_not_held(ubuntu.path(), 1000), None);
    }

    /// As on Raspberry Pi OS, whose firmware turns it off.
    #[test]
    fn a_kernel_without_the_memory_controller_holds_no_memory_limit() {
        let pi = hierarchy("cpuset cpu io pids\n", Some("cpu pids\n"));
        let why = memory_not_held(pi.path(), 1000).unwrap();
        assert!(why.contains("no memory controller"), "{why}");
    }

    #[test]
    fn a_controller_not_delegated_is_not_held_and_said_so() {
        let kept = hierarchy("cpu io memory pids\n", Some("cpu pids\n"));
        let why = memory_not_held(kept.path(), 1000).unwrap();
        assert!(why.contains("not delegated"), "{why}");
        assert!(why.contains("user@1000.service"), "{why}");
    }

    /// No hierarchy, as on macOS, or no manager for this user.
    #[test]
    fn a_list_that_cannot_be_read_is_no_controller() {
        let none = tempfile::tempdir().unwrap();
        assert!(
            memory_not_held(none.path(), 1000)
                .unwrap()
                .contains("cannot read")
        );
        let no_manager = hierarchy("memory\n", None);
        let why = memory_not_held(no_manager.path(), 1000).unwrap();
        assert!(why.contains("cannot read"), "{why}");
    }
}
