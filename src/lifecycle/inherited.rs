//! What a program enclos starts inherits from enclos's caller: its standard
//! streams, never another descriptor. A lock, pipe or terminal the caller
//! passed on would otherwise stay open in what enclos starts for as long as
//! that runs: in a proxy a `connect` started, until `sandbox stop`, so that
//! whoever waits on such a lock waits until then; in a session's program,
//! as a way out of its sandbox to whatever the descriptor opens.

/// Marks every descriptor this process holds above its standard streams
/// close-on-exec, so that no program it starts afterwards inherits one; this
/// process still uses them. Called first, while this process runs one
/// thread and before it opens a descriptor a program must inherit: those,
/// such as a session's marker, are made later without the flag. Not for a
/// command that starts a session's program (`holder join` and `holder
/// enter`, `inside`): what
/// it inherited comes from enclos, the session's marker among it.
pub fn pass_on_none() {
    close_fds::set_fds_cloexec(3, &[]);
}
