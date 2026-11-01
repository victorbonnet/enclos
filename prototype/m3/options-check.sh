#!/bin/bash
# Whether each target distribution's bubblewrap has every option the
# prototype's compiled arguments use (design §14: 0.8.0 on Debian 12 is the
# oldest). Each distribution's package is installed in a container of that
# distribution and its `bwrap --help` read; nothing runs bubblewrap. Needs
# Docker and pulls images, so CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/60-options.md"
tmp="$RESULTS_DIR/options"
mkdir -p "$tmp"

compile_policy --new-session
# The wrap step's output: the options of the masks are not in the compiled file.
mapfile -t used < <(python3 -I "$M3/wrap.py" "$SBX_COMPILED/compiled.json" \
    | tr '\0' '\n' | grep -- '^--' | sort -u)

images=(debian:bookworm ubuntu:24.04 debian:trixie)
for img in "${images[@]}"; do
    docker run --rm "$img" sh -c \
        'apt-get update -qq >/dev/null && apt-get install -y -qq bubblewrap >/dev/null 2>&1;
         dpkg-query -W -f "package: \${Version}\n" bubblewrap; bwrap --help 2>&1' \
        >"$tmp/${img//[:.]/-}.txt" 2>&1
done

{
    echo "# bubblewrap's options by distribution ($(uname -m))"
    section "Packages"
    for img in "${images[@]}"; do
        echo "- $img: $(grep -m1 '^package:' "$tmp/${img//[:.]/-}.txt" || echo 'not installed')"
    done
    section "Options the compiled arguments use"
    printf '| option |'; printf ' %s |' "${images[@]}"; echo
    printf '| --- |'; printf ' --- |%.0s' "${images[@]}"; echo
    for opt in "${used[@]}"; do
        printf '| `%s` |' "$opt"
        for img in "${images[@]}"; do
            if grep -qE -- "^ *${opt}( |$)" "$tmp/${img//[:.]/-}.txt"; then printf ' yes |'; else printf ' **no** |'; fi
        done
        echo
    done
} >"$out"
cat "$out"
