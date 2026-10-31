//! The compiled seccomp filter as BPF programs for this architecture. Pure:
//! nothing here loads a program, [`super::apply`] does.

use seccompiler::{BpfProgram, TargetArch, sock_filter};
use serde_json::{Value, json};

use super::InsideError;
use crate::backend::bubblewrap::compile::SeccompFilter;

/// What the kernel returns for a call `clone3` needs refused this way.
const ENOSYS: u32 = 38;

/// The compiled names no such architecture has, skipped by name: any other
/// name not found is refused, so a call is never dropped by a typing mistake.
fn absent_on(arch: TargetArch) -> &'static [&'static str] {
    match arch {
        TargetArch::aarch64 => &["ioperm", "iopl", "uselib"],
        _ => &[],
    }
}

/// `spec`'s programs for `arch`, all to be loaded: seccompiler gives a filter
/// one action, so `EPERM` and `ENOSYS` are one each.
pub(super) fn programs(
    spec: &SeccompFilter,
    arch: TargetArch,
) -> Result<Vec<BpfProgram>, InsideError> {
    if !matches!(arch, TargetArch::x86_64 | TargetArch::aarch64) {
        return Err(InsideError::Architecture(format!("{arch:?}")));
    }
    let refused = errno(&spec.errno)?;
    let mut rules: Vec<Value> = Vec::new();
    for name in &spec.deny {
        if !absent_on(arch).contains(&name.as_str()) {
            rules.push(json!({ "syscall": name }));
        }
    }
    // The kernel reads a request as 32 bits, so the bits above are ignored
    // here too: a caller cannot pass one with them set.
    for request in spec.ioctl.values() {
        rules.push(json!({
            "syscall": "ioctl",
            "args": [{ "index": 1, "type": "dword", "op": "eq", "val": request }],
        }));
    }
    for flag in spec.clone_flags.values() {
        for call in ["unshare", "clone"] {
            rules.push(json!({
                "syscall": call,
                "args": [{ "index": 0, "type": "qword", "op": { "masked_eq": flag }, "val": flag }],
            }));
        }
    }
    let enosys: Vec<Value> = spec
        .enosys
        .iter()
        .map(|name| json!({ "syscall": name }))
        .collect();
    let filters = json!({
        "refused": filter(refused, rules),
        "enosys": filter(ENOSYS, enosys),
    });
    let mut built = seccompiler::compile_from_json(filters.to_string().as_bytes(), arch)
        .map_err(|e| InsideError::Filter(e.to_string()))?;
    let mut programs = Vec::new();
    programs.extend(built.remove("refused"));
    programs.extend(built.remove("enosys"));
    if arch == TargetArch::x86_64 {
        programs.push(no_x32());
    }
    Ok(programs)
}

fn filter(errno: u32, rules: Vec<Value>) -> Value {
    json!({
        "mismatch_action": "allow",
        "match_action": { "errno": errno },
        "filter": rules,
    })
}

fn errno(name: &str) -> Result<u32, InsideError> {
    match name {
        "EPERM" => Ok(1),
        other => Err(InsideError::Errno(other.to_owned())),
    }
}

/// Ends a process that makes an x32 call. x32 shares x86_64's audit
/// architecture and numbers its calls from `0x4000_0000`, so seccompiler's
/// check of the architecture passes it and no listed number matches: without
/// this, `keyctl` plus that bit gets past a filter of named calls. libseccomp
/// treats it as another architecture, which ends the process; so does this.
/// Numbers above the range, such as `-1`, stay the kernel's to refuse.
fn no_x32() -> BpfProgram {
    const LOAD_NUMBER: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS, at offset 0
    const JUMP_IF_AT_LEAST: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K
    const ALLOW: u32 = 0x7fff_0000; // SECCOMP_RET_ALLOW
    const KILL_PROCESS: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
    const X32_FIRST: u32 = 0x4000_0000;
    const ABOVE_X32: u32 = 0x8000_0000;
    let step = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        step(LOAD_NUMBER, 0, 0, 0),
        step(JUMP_IF_AT_LEAST, 2, 0, ABOVE_X32),
        step(JUMP_IF_AT_LEAST, 0, 1, X32_FIRST),
        step(RETURN, 0, 0, KILL_PROCESS),
        step(RETURN, 0, 0, ALLOW),
    ]
}

#[cfg(test)]
mod tests;
