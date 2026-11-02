#!/bin/bash
# The prototype sandbox's files, programs and system calls (design §14,
# M3-02): broad reads with the deny list not mounted, denied paths inside the
# workspace masked (planted, or missing and so a folder) with the rest of it
# as granted, deny entries that are links with their targets hidden, writes to the home and the workspace only, the home and
# workspace unmovable, programs run from the
# workspace (directly, through the loader and from a memfd), the seccomp list, other processes (whether /proc/<pid> exists is
# the control: the host's own read of a process's environ never worked), the
# host's loopback, DNS and vsock. Each probe runs on the host as
# its control, then in the sandbox in five modes:
#
#   bubblewrap only        no Landlock, no seccomp: what the mounts and
#                          namespaces alone do
#   + seccomp, no Landlock what ADR 0037 runs where the kernel has no Landlock
#   + Landlock, no seccomp what Landlock alone adds
#   full                   Landlock and seccomp, as on Ubuntu and Debian
#   --new-session          Landlock, no seccomp, bubblewrap's setsid on
#                          (TIOCSTI only)
#
# Acts on the host (plants files in the home, runs bubblewrap): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/10-sandbox.md"
tmp="$RESULTS_DIR/sandbox"
mkdir -p "$tmp"

# --- what the probes look for
planted=()
for d in "${DENY[@]}"; do
    [ "$d" = "$H/.enclos" ] && continue
    [ "$d" = "$WORK/denied-file" ] && continue
    [ "$d" = "$WORK/denied-missing" ] && continue
    [ "$d" = "$H/proto-linked-entry" ] && continue
    [ "$d" = "$WORK/denied-link" ] && continue
    mkdir -p "$d"
    echo planted >"$d/enclos-proto-planted"
    planted+=("$d/enclos-proto-planted")
done
echo planted >"$WORK/denied-file"
rm -rf "$WORK/denied-missing"  # the first run leaves the mask's mount point there
echo kept >"$WORK/kept-file"
# Deny entries that are links, as GNU stow sets a home up: their targets, here
# or out of the workspace, must not read through a folder bound back.
mkdir -p "$H/proto-linked-target"
mkdir -p "$H/proto-linked-holder/entry"
echo planted >"$H/proto-linked-holder/entry/enclos-proto-planted"
echo kept >"$H/proto-linked-holder/enclos-proto-beside"
echo planted >"$H/proto-linked-target/workspace-token"
echo kept >"$H/proto-linked-target/enclos-proto-beside"
rm -rf "$H/proto-linked-entry" "$WORK/denied-link"
ln -s proto-linked-holder/entry "$H/proto-linked-entry"
ln -s ../proto-linked-target/workspace-token "$WORK/denied-link"
mkdir -p "$WORK/kept-folder"
other="$H/.enclos/sandboxes/other/home"
mkdir -p "$other"
echo planted >"$other/enclos-proto-planted"
echo readable >"$H/enclos-proto-readable.txt"
# dash, not a coreutils program: a multi-call coreutils runs by the name it has.
cp "$(readlink -f /bin/sh)" "$SBX_HOME/sh-copy"
cp "$(readlink -f /bin/sh)" "$WORK/sh-copy"
printf '#!/bin/sh\necho ran\n' >"$WORK/hello.sh"
chmod +x "$WORK/hello.sh"

sleep 900 &
sleeper=$!
python3 -I -m http.server --bind 127.0.0.1 18999 >/dev/null 2>&1 &
listener=$!
trap 'kill "$sleeper" "$listener" 2>/dev/null' EXIT
sleep 1

probes=()
for f in "${planted[@]}"; do probes+=("read $f"); done
probes+=(
    "read $WORK/denied-file"
    "write $WORK/denied-folder/enclos-proto-w"
    "open-write $WORK/denied-file"
    "rename $WORK/denied-folder"
    "exists $WORK/denied-missing"
    "read $WORK/denied-missing"
    "write $WORK/denied-missing/enclos-proto-w"
    "rename $WORK/denied-missing"
    "read $H/proto-linked-entry/enclos-proto-planted"
    "read $H/proto-linked-holder/entry/enclos-proto-planted"
    "read $H/proto-linked-holder/enclos-proto-beside"
    "read $WORK/denied-link"
    "read $H/proto-linked-target/workspace-token"
    "read $H/proto-linked-target/enclos-proto-beside"
    "read $WORK/kept-file"
    "write $WORK/kept-folder/enclos-proto-w"
    "rename $WORK/kept-folder"
    "exists $H/.ssh"
    "read $other/enclos-proto-planted"
    "exists $H/.enclos/sandboxes/other"
    "read $H/enclos-proto-readable.txt"
    "read /etc/os-release"
    "read $M3/README.md"
    "write $SBX_HOME/enclos-proto-w"
    "write $WORK/enclos-proto-w"
    "write $H/enclos-proto-w"
    "write $M3/enclos-proto-w"
    "write $SBX_COMPILED/enclos-proto-w"
    "write $SBX_RUN/enclos-proto-w"
    "write /var/tmp/enclos-proto-w"
    "leave /tmp/enclos-proto-left"
    "rename $SBX_HOME"
    "rename $WORK"
    "exec $SBX_HOME/sh-copy"
    "exec $WORK/sh-copy"
    "exec $WORK/hello.sh"
    "exec-loader $WORK/sh-copy"
    "exec-memfd $WORK/sh-copy"
    "unshare user"
    "unshare mount"
    "unshare net"
    "mount"
    "keyctl"
    "bpf"
    "perf_event_open"
    "userfaultfd"
    "io_uring"
    "kill $sleeper"
    "ptrace $sleeper"
    "exists /proc/$sleeper"
    "connect-tcp 127.0.0.1 18999"
    "connect-tcp 1.1.1.1 443"
    "connect-vsock 2 9"
    "connect-vsock 1 9"
    "socket-family 40"
    "socket-family 38 5"
    "dns example.com"
)

modes=(
    "bwrap|bubblewrap only|off|off"
    "seccomp|+ seccomp, no Landlock|off|on"
    "landlock|+ Landlock, no seccomp|auto|off"
    "full|full|auto|on"
)
left=()
for m in "${modes[@]}"; do
    IFS='|' read -r key _ ll sc <<<"$m"
    SBX_LANDLOCK=$ll SBX_SECCOMP=$sc "$M3/sbx.sh" -- /usr/bin/python3 -I "$M3/probe.py" "${probes[@]}" \
        >"$tmp/$key.tsv" 2>"$tmp/$key.err"
    echo "exit $?" >>"$tmp/$key.err"
    # A file the sandbox left in its own /tmp must not be in the host's.
    if [ -e /tmp/enclos-proto-left ]; then left+=("$key: found in the host's /tmp"); rm -f /tmp/enclos-proto-left
    else left+=("$key: not in the host's /tmp"); fi
done
python3 -I "$M3/probe.py" "${probes[@]}" >"$tmp/host.tsv" 2>"$tmp/host.err"
rm -f /tmp/enclos-proto-left

# TIOCSTI needs a terminal: pty-run.py gives each run one as its controlling
# terminal, as a user's session has.
tio() { python3 -I "$M3/pty-run.py" -- "$@" 2>&1 | grep -v '^inside:' | grep tiocsti; }
tio /usr/bin/python3 -I "$M3/probe.py" tiocsti >"$tmp/tio-host.tsv"
for m in "${modes[@]}"; do
    IFS='|' read -r key _ ll sc <<<"$m"
    SBX_LANDLOCK=$ll SBX_SECCOMP=$sc tio "$M3/sbx.sh" -- /usr/bin/python3 -I "$M3/probe.py" tiocsti >"$tmp/tio-$key.tsv"
done
SBX_NEW_SESSION=1 SBX_SECCOMP=off tio "$M3/sbx.sh" -- /usr/bin/python3 -I "$M3/probe.py" tiocsti >"$tmp/tio-newsession.tsv"

cols=("host=$tmp/host.tsv")
tcols=("host=$tmp/tio-host.tsv")
for m in "${modes[@]}"; do
    IFS='|' read -r key label _ _ <<<"$m"
    cols+=("$label=$tmp/$key.tsv")
    tcols+=("$label=$tmp/tio-$key.tsv")
done
tcols+=("--new-session, no seccomp=$tmp/tio-newsession.tsv")

compile_policy  # the full mode's, without --new-session, for the record
{
    echo "# The sandbox: files, programs, system calls ($(uname -m))"
    section "What inside.py applied in each mode"
    for m in "${modes[@]}"; do
        IFS='|' read -r key label _ _ <<<"$m"
        echo "- $label: $(grep -h '^inside:\|^exit\|^bwrap:' "$tmp/$key.err" | tr '\n' ' ')"
    done
    section "Probes"
    echo "\`ok\` means the operation succeeded; an error name means it was refused with that error."
    echo
    echo "Where the host column already refuses, the row shows nothing about the sandbox: read \`bpf\`, \`perf_event_open\` and \`userfaultfd\` against the host's sysctls in 00-setup.md, and what seccomp adds against the bubblewrap-only column, since the filter's errno (EPERM) is also the kernel's."
    echo
    echo "\`read $WORK/denied-file\` reads 0 bytes where the mask holds, and 8 on the host. The host column's \`denied-missing\` rows come after the sandbox modes, so they show the empty folder a mask leaves there."
    echo
    echo "\`exec-loader\` and \`exec-memfd\` run the copy \`exec\` runs: \`ok\` where \`exec $WORK/sh-copy\` is refused shows a way round the execute rule. \`connect-vsock\` is read against the host's column: the same error in the sandbox shows a network namespace does not stand in its way. \`socket-family 40\` is \`AF_VSOCK\` and \`socket-family 38 5\` \`AF_ALG\`: EPERM with the filter, and any other answer without it, shows the rule on families."
    echo
    python3 -I "$M3/table.py" "${cols[@]}"
    section "TIOCSTI (under a terminal of its own)"
    echo "dev.tty.legacy_tiocsti: $(cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null || echo absent). At 0 the kernel refuses TIOCSTI to every unprivileged process (EIO). seccomp runs before the ioctl, so EPERM where the others read EIO shows the filter matched; whether --new-session alone refuses it needs a host with the setting at 1 (a VM)."
    echo
    python3 -I "$M3/table.py" "${tcols[@]}"
    section "A file left in the sandbox's /tmp"
    printf -- '- %s\n' "${left[@]}"
    section "The compiled policy (full mode)"
    fence <"$SBX_COMPILED/compiled.json"
} >"$out"
cat "$out"
