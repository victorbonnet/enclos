use std::collections::BTreeMap;

use super::*;
use crate::backend::SandboxContext;
use crate::backend::bubblewrap::CompiledSandbox;
use crate::layout::Layout;
use crate::model::policy::Policy;

const ALLOW: u32 = 0x7fff_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
const ERRNO: u32 = 0x0005_0000;
const EPERM: u32 = ERRNO | 1;
const ENOSYSTEM: u32 = ERRNO | 38;

const AUDIT_X86_64: u32 = 0xC000_003E;
const AUDIT_AARCH64: u32 = 0xC000_00B7;
const AUDIT_I386: u32 = 0x4000_0003;
const AUDIT_ARM: u32 = 0x4000_0028;

const X32: i32 = 0x4000_0000;

/// One architecture's numbers for the calls these tests make.
struct Calls {
    arch: TargetArch,
    audit: u32,
    getpid: i32,
    keyctl: i32,
    ioctl: i32,
    unshare: i32,
    clone: i32,
    clone3: i32,
}

const X86_64: Calls = Calls {
    arch: TargetArch::x86_64,
    audit: AUDIT_X86_64,
    getpid: 39,
    keyctl: 250,
    ioctl: 16,
    unshare: 272,
    clone: 56,
    clone3: 435,
};

const AARCH64: Calls = Calls {
    arch: TargetArch::aarch64,
    audit: AUDIT_AARCH64,
    getpid: 172,
    keyctl: 219,
    ioctl: 29,
    unshare: 97,
    clone: 220,
    clone3: 435,
};

const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;
const TIOCGWINSZ: u64 = 0x5413;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_THREAD_FLAGS: u64 = 0x003d_0f00;

/// What the kernel hands a filter: `struct seccomp_data`.
struct Call {
    number: i32,
    audit: u32,
    args: [u64; 6],
}

impl Call {
    fn word(&self, offset: u32) -> u32 {
        let low = |value: u64| value as u32;
        let high = |value: u64| (value >> 32) as u32;
        match offset {
            0 => self.number as u32,
            4 => self.audit,
            16.. => {
                let arg = self.args[((offset - 16) / 8) as usize];
                match offset % 8 {
                    0 => low(arg),
                    _ => high(arg),
                }
            }
            other => panic!("no word at {other}"),
        }
    }
}

/// Runs a program as the kernel does, on the instructions these use.
fn run(program: &BpfProgram, call: &Call) -> u32 {
    let (mut pc, mut accumulator) = (0, 0u32);
    loop {
        let step = &program[pc];
        pc += 1;
        let k = step.k;
        let taken = |yes: bool| match yes {
            true => step.jt as usize,
            false => step.jf as usize,
        };
        match step.code {
            0x20 => accumulator = call.word(k),
            0x54 => accumulator &= k,
            0x05 => pc += k as usize,
            0x15 => pc += taken(accumulator == k),
            0x25 => pc += taken(accumulator > k),
            0x35 => pc += taken(accumulator >= k),
            0x06 => return k,
            other => panic!("instruction {other:#x}"),
        }
    }
}

/// What every program says together: the kernel takes the action that goes
/// furthest, an ending first and allowing last.
fn verdict(programs: &[BpfProgram], call: &Call) -> u32 {
    let rank = |action: u32| action as i32;
    programs
        .iter()
        .map(|p| run(p, call))
        .min_by_key(|a| rank(*a))
        .unwrap()
}

fn compiled_filter() -> SeccompFilter {
    let layout = Layout::at("/nonexistent-enclos-test/alice/.enclos");
    let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 41001);
    let text = crate::backend::bubblewrap::compile(&Policy::default(), &ctx)
        .unwrap()
        .text;
    serde_json::from_str::<CompiledSandbox>(&text)
        .unwrap()
        .seccomp
}

fn built(calls: &Calls) -> Vec<BpfProgram> {
    programs(&compiled_filter(), calls.arch).unwrap()
}

fn asked(calls: &Calls, number: i32, args: [u64; 6]) -> Call {
    Call {
        number,
        audit: calls.audit,
        args,
    }
}

fn with_arg(index: usize, value: u64) -> [u64; 6] {
    let mut args = [0; 6];
    args[index] = value;
    args
}

#[test]
fn a_listed_call_is_refused_and_an_unlisted_one_allowed() {
    for calls in [X86_64, AARCH64] {
        let programs = built(&calls);
        let keyctl = asked(&calls, calls.keyctl, [0; 6]);
        assert_eq!(verdict(&programs, &keyctl), EPERM);
        let getpid = asked(&calls, calls.getpid, [0; 6]);
        assert_eq!(verdict(&programs, &getpid), ALLOW);
    }
}

#[test]
fn a_listed_ioctl_is_refused_with_any_high_bits_and_another_allowed() {
    for calls in [X86_64, AARCH64] {
        let programs = built(&calls);
        for request in [TIOCSTI, TIOCLINUX, 0xffff_ffff_0000_0000 | TIOCSTI] {
            let call = asked(&calls, calls.ioctl, with_arg(1, request));
            assert_eq!(verdict(&programs, &call), EPERM, "{request:#x}");
        }
        let call = asked(&calls, calls.ioctl, with_arg(1, TIOCGWINSZ));
        assert_eq!(verdict(&programs, &call), ALLOW);
    }
}

#[test]
fn a_new_namespace_is_refused_in_unshare_and_clone_and_threads_allowed() {
    for calls in [X86_64, AARCH64] {
        let programs = built(&calls);
        for number in [calls.unshare, calls.clone] {
            let call = asked(&calls, number, with_arg(0, CLONE_NEWUSER | 0x11));
            assert_eq!(verdict(&programs, &call), EPERM);
        }
        let thread = asked(&calls, calls.clone, with_arg(0, CLONE_THREAD_FLAGS));
        assert_eq!(verdict(&programs, &thread), ALLOW);
    }
}

#[test]
fn clone3_gets_enosys_so_the_c_library_falls_back_to_clone() {
    for calls in [X86_64, AARCH64] {
        let call = asked(&calls, calls.clone3, [0; 6]);
        assert_eq!(verdict(&built(&calls), &call), ENOSYSTEM);
    }
}

#[test]
fn a_call_of_another_architecture_ends_the_process() {
    for (calls, audit) in [(X86_64, AUDIT_I386), (AARCH64, AUDIT_ARM)] {
        let programs = built(&calls);
        let call = Call {
            number: calls.getpid,
            audit,
            args: [0; 6],
        };
        assert_eq!(verdict(&programs, &call), KILL_PROCESS);
    }
}

/// x32 passes the check of the architecture, with numbers no rule names.
#[test]
fn an_x32_call_ends_the_process() {
    let programs = built(&X86_64);
    let keyctl = asked(&X86_64, X86_64.keyctl | X32, [0; 6]);
    assert_eq!(verdict(&programs, &keyctl), KILL_PROCESS);
}

#[test]
fn a_number_above_x32_is_left_to_the_kernel() {
    let call = asked(&X86_64, -1, [0; 6]);
    assert_eq!(verdict(&built(&X86_64), &call), ALLOW);
}

#[test]
fn only_x86_64_has_the_x32_program() {
    assert_eq!(built(&X86_64).len(), built(&AARCH64).len() + 1);
}

#[test]
fn a_name_this_architecture_lacks_is_skipped_only_if_known() {
    let mut spec = compiled_filter();
    assert!(spec.deny.contains(&"uselib".to_owned()));
    assert!(programs(&spec, TargetArch::aarch64).is_ok());
    spec.deny.push("no_such_call".to_owned());
    for arch in [TargetArch::aarch64, TargetArch::x86_64] {
        let err = programs(&spec, arch).unwrap_err().to_string();
        assert!(err.contains("no_such_call"), "{err}");
    }
}

#[test]
fn an_errno_nothing_maps_is_refused() {
    let mut spec = compiled_filter();
    spec.errno = "EWHAT".to_owned();
    let err = programs(&spec, TargetArch::x86_64).unwrap_err();
    assert!(err.to_string().contains("EWHAT"), "{err}");
}

#[test]
fn an_architecture_outside_the_supported_ones_is_refused() {
    let spec = SeccompFilter {
        errno: "EPERM".to_owned(),
        deny: Vec::new(),
        ioctl: BTreeMap::new(),
        clone_flags: BTreeMap::new(),
        enosys: Vec::new(),
    };
    let err = programs(&spec, TargetArch::riscv64).unwrap_err();
    assert!(err.to_string().contains("riscv64"), "{err}");
}
