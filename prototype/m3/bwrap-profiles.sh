#!/bin/sh
# Prints the AppArmor profiles named for bubblewrap in $1 (default
# /etc/apparmor.d), separated by spaces, or nothing. Read-only.
dir=${1:-/etc/apparmor.d}
found=""
for name in bwrap bwrap-userns-restrict usr.bin.bwrap; do
    [ -e "$dir/$name" ] && found="$found $dir/$name"
done
printf '%s\n' "${found# }"
