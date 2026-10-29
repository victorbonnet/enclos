#!/bin/bash
# The prototype sandbox's files, programs and system calls (design §14,
# M3-02): broad reads with the deny list not mounted, writes to the home and
# the workspace only, the home and workspace unmovable, programs run from the
# workspace, the seccomp list, other processes and their start-up
# environment, the host's loopback and DNS. Each probe runs on the host as
# its control, then in the sandbox in five modes:
#
#   bubblewrap only        no Landlock, no seccomp: what the mounts and
#                          namespaces alone do
#   + seccomp, no Landlock what ADR 0037 runs where the kernel has no Landlock
#   + Landlock, no seccomp what Landlock alone adds
#   full                   Landlock and seccomp, as on Ubuntu and Debian
#   full, --new-session    the same, bubblewrap's setsid on (TIOCSTI only)
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
    mkdir -p "$d"
    echo planted >"$d/enclos-proto-planted"
    planted+=("$d/enclos-proto-planted")
done
other="$H/.enclos/sandboxes/other/home"
mkdir -p "$other"
echo planted >"$other/enclos-proto-planted"
echo readable >"$H/enclos-proto-readable.txt"
cp /usr/bin/true "$SBX_HOME/true-copy"
cp /usr/bin/true "$WORK/true-copy"
printf '#!/bin/sh\necho ran\n' >"$WORK/hello.sh"
chmod +x "$WORK/hello.sh"

marker="enclos-proto-marker-$$"
env ENCLOS_PROTO_MARKER="$marker" sleep 900 &
sleeper=$!
python3 -I -m http.server --bind 127.0.0.1 18999 >/dev/null 2>&1 &
listener=$!
trap 'kill "$sleeper" "$listener" 2>/dev/null' EXIT
sleep 1

probes=()
for f in "${planted[@]}"; do probes+=("read $f"); done
probes+=(
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
    "exec $SBX_HOME/true-copy"
    "exec $WORK/true-copy"
    "exec $WORK/hello.sh"
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
    "environ $marker"
    "connect-tcp 127.0.0.1 18999"
    "connect-tcp 1.1.1.1 443"
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
    python3 -I "$M3/table.py" "${cols[@]}"
    section "TIOCSTI (under a terminal of its own)"
    echo "dev.tty.legacy_tiocsti: $(cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null || echo absent). At 0 the kernel refuses TIOCSTI to every unprivileged process (EIO), so neither seccomp nor --new-session is shown by these rows; that needs a host with the setting at 1 (a VM)."
    echo
    python3 -I "$M3/table.py" "${tcols[@]}"
    section "A file left in the sandbox's /tmp"
    printf -- '- %s\n' "${left[@]}"
    section "The compiled policy (full mode)"
    fence <"$SBX_COMPILED/compiled.json"
} >"$out"
cat "$out"
