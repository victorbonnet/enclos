//! Probes that a folder the sandbox may change inside cannot itself move:
//! each makes a call the filesystem refuses whatever the policy, so nothing
//! moves even if the sandbox lets it through.

use std::path::Path;

use super::{End, UNPREPARED, answered, call};
use crate::probes::{OwnReading, Probe, sh_quote};

/// A folder renamed or removed: refused by a read-only mount (`EROFS`),
/// which comes first, or because it is a mount point (`EBUSY`). The
/// filesystem's own refusal of a folder that is not empty means the call
/// got past both.
pub(super) const MOVED: OwnReading = OwnReading {
    label: "folder held: EROFS or EBUSY",
    read: |succeeded, output| {
        answered(
            &["EROFS", "EBUSY"],
            &["ENOTEMPTY", "EEXIST"],
            "the call reached the filesystem, which refused it only because a folder was not empty",
            succeeded,
            output,
        )
    },
    when_control_fails: Some(
        "outside the sandbox, the filesystem did not refuse it as it refuses a folder that is not empty",
    ),
};

/// What refused folder moves look like outside the sandbox.
const NOT_EMPTY: &[&str] = &["ENOTEMPTY", "EEXIST"];

/// Renames `folder` onto a folder beside it, which the program makes and
/// fills first, so that the filesystem refuses the rename whatever the
/// policy and nothing moves. Where the folder's parent is read-only, as the
/// sandbox has its home's and each workspace's, the folder beside it cannot
/// be made (`EROFS`), and the rename gets the same refusal, as both are
/// checked on the one mount. What the program made is removed.
pub(crate) fn rename_beside(folder: &Path, tag: u32) -> Probe {
    let beside = folder
        .parent()
        .unwrap_or(folder)
        .join(format!("enclos-probe-{tag}"));
    let code = |end: End| {
        format!(
            r#"my ($folder, $beside) = @ARGV; my $made = mkdir($beside);
if ($made) {{ if (!open(my $f, ">", "$beside/kept")) {{ my $e = word(0); rmdir($beside); print "could not prepare: $e\n"; exit 2 }} }}
elsif (!$!{{EROFS}}) {UNPREPARED}
my $w = word(rename($folder, $beside));
if ($made && $w ne "ok") {{ unlink("$beside/kept"); rmdir($beside) }}
$w = "ok: $folder is now at $beside" if $w eq "ok";
{}"#,
            end.perl()
        )
    };
    call(
        "renames",
        format!("rename {}", folder.display()),
        code,
        &[sh_quote(folder), sh_quote(&beside)],
        MOVED,
        NOT_EMPTY,
    )
}

/// Removes the sandbox `home`, which holds `tmp/`, made again first: the
/// filesystem refuses to remove a folder that is not empty, whatever the
/// policy, and the program stops before the call if it finds it empty.
pub(crate) fn remove_home(home: &Path) -> Probe {
    let code = |end: End| {
        format!(
            r#"my ($home) = @ARGV; mkdir("$home/tmp");
if (!opendir(my $d, $home)) {UNPREPARED}
elsif (!grep {{ $_ ne "." && $_ ne ".." }} readdir($d)) {{ print "could not prepare: it is empty\n"; exit 2 }}
my $w = word(rmdir($home));
$w = "ok: $home was removed" if $w eq "ok";
{}"#,
            end.perl()
        )
    };
    call(
        "writable folders",
        "remove the sandbox home".to_owned(),
        code,
        &[sh_quote(home)],
        MOVED,
        NOT_EMPTY,
    )
}
