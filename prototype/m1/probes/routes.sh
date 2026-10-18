#!/bin/bash
# Host-service escape probes (design §5, ADR 0016). Each probe runs twice:
# WITHOUT = the compiled policy minus the fragment(s) that close its route
# (plus any rule that re-opens it), WITH = the full compiled policy. A route is
# reported open or closed from the probe's result, never assumed.
#
#   ./probes/routes.sh                 every route
#   ./probes/routes.sh dns keychain    only routes whose name starts with these
#
# Non-destructive by construction: lookups instead of actions where possible,
# a harmless URL for LaunchServices, a read-only Apple Event to Finder (8 s
# timeout), a dummy launchd label running /usr/bin/true (removed at once), a
# dummy preferences domain (deleted at once), the Keychain's lock settings only,
# connect() with nothing sent, read-only crontab/atq. No synthetic input is
# posted, no crontab or at job written. Anything created is removed and printed.
set -u
# These probes act on the host (an Apple Event to Finder, a dummy launchd job, a
# preferences domain, a URL opened in the browser). After an incident on the
# development Mac they run only in a disposable macOS VM.
if [ "${ENCLOS_PROBE_VM:-}" != 1 ]; then
    echo "routes.sh runs only in a disposable macOS VM: set ENCLOS_PROBE_VM=1 there." >&2
    exit 1
fi
M1="$(cd "$(dirname "$0")/.." && pwd -P)"
source "$M1/env.sh"
SBX="$M1/sbx.sh"
PY="$(uv python find 2>/dev/null)"
LABEL="org.enclos.probe.$$"
SSH_SOCK="$(launchctl getenv SSH_AUTH_SOCK)"
UIDN="$(id -u)"
KC="$REAL_HOME/Library/Keychains/login.keychain-db"
AE="osascript -e 'with timeout of 8 seconds' -e 'tell application \"Finder\" to count windows' -e 'end timeout'"

# name | fragments left out for WITHOUT ("none" = plain allow default) | extra SBPL for WITHOUT | probe command
ROUTES=(
  "launchservices|40||open -g https://example.com"
  "appleevents|41||$AE"
  "launchd-submit|42|(allow job-creation)|launchctl submit -l $LABEL -- /usr/bin/true"
  "launchd-bootstrap|42|(allow job-creation)|launchctl bootstrap gui/$UIDN \$HOME/$LABEL.plist"
  "preferences|43||defaults write org.enclos.probe probe -string written"
  "input-windowserver|44||$PROBE mach com.apple.windowserver.active"
  "input-pasteboard|44||pbpaste >/dev/null"
  "login-items-btm|45||$PROBE mach com.apple.backgroundtaskmanagementagent"
  "login-items-register|45||$PROBE mach com.apple.xpc.loginitemregisterd"
  "crontab|none||crontab -l >/dev/null"
  "at|none||atq >/dev/null"
  "unix-ssh-agent|30||$PROBE unix $SSH_SOCK"
  "unix-docker|30||$PROBE unix /var/run/docker.sock"
  "keychain|20 46||security show-keychain-info $KC"
  "keychain-securityd|46||$PROBE mach com.apple.SecurityServer"
  "dns-getaddrinfo|30 47||$PY -I -c 'import socket; print(socket.getaddrinfo(\"example.com\", 443)[0][4])'"
  "dns-dscacheutil|30 47||dscacheutil -q host -a name example.com | grep -m1 address"
  "dns-dnssd-mach|47||$PROBE mach com.apple.dnssd.service"
  "dns-udp53|30||$PROBE tcp 1.1.1.1 53"
  "direct-tcp|30||$PROBE tcp 1.1.1.1 443"
)

interpret() {  # name status output -> open|closed
    local name="$1" st="$2" out="$3"
    case "$name" in
      appleevents)  # delivered = an answer, or a wait on Finder/TCC (-1712) or a TCC refusal (-1743)
        [[ "$out" =~ ^[0-9]+$ || "$out" == *-1712* || "$out" == *-1743* ]] && echo open || echo closed ;;
      launchd-*) launchctl list | grep -q "$LABEL" && echo open || echo closed ;;
      preferences) defaults read org.enclos.probe probe >/dev/null 2>&1 && echo open || echo closed ;;
      dns-dscacheutil) [[ "$out" == *address* ]] && echo open || echo closed ;;
      *) [ "$st" = 0 ] && echo open || echo closed ;;
    esac
}

cleanup() {  # remove anything a probe managed to create, and say so
    if launchctl list | grep -q "$LABEL"; then
        launchctl bootout "gui/$UIDN/$LABEL" 2>/dev/null || launchctl remove "$LABEL" 2>/dev/null
        echo "    cleanup: removed launchd job $LABEL" >&2
    fi
    if defaults read org.enclos.probe >/dev/null 2>&1; then
        defaults delete org.enclos.probe
        echo "    cleanup: deleted preferences domain org.enclos.probe" >&2
    fi
    local f
    for f in "$REAL_HOME/Library/Preferences/org.enclos.probe.plist" "$SBX_HOME/Library/Preferences/org.enclos.probe.plist"; do
        if [ -e "$f" ]; then rm -f "$f"; echo "    cleanup: removed ${f/#$REAL_HOME/\$HOME}" >&2; fi
    done
    return 0
}

cat >"$SBX_HOME/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
</dict></plist>
EOF

start="$(date '+%Y-%m-%d %H:%M:%S')"
printf '%-22s %-8s %-8s %s\n' ROUTE WITHOUT WITH "EVIDENCE (WITH; then WITHOUT)"
for r in "${ROUTES[@]}"; do
    IFS='|' read -r name frags extra cmd <<<"$r"
    if [ $# -gt 0 ]; then
        match=0; for want in "$@"; do [[ "$name" == "$want"* ]] && match=1; done
        [ "$match" = 1 ] || continue
    fi
    cleanup
    if [ "$frags" = none ]; then
        out_wo=$(SBX_POLICY=none "$SBX" -- /bin/sh -c "$cmd" 2>&1); st_wo=$?
    else
        out_wo=$(SBX_WITHOUT="$frags" SBX_EXTRA_RULES="$extra" "$SBX" -- /bin/sh -c "$cmd" 2>&1); st_wo=$?
    fi
    v_wo=$(interpret "$name" "$st_wo" "$out_wo"); cleanup
    out_w=$("$SBX" -- /bin/sh -c "$cmd" 2>&1); st_w=$?
    v_w=$(interpret "$name" "$st_w" "$out_w"); cleanup
    printf '%-22s %-8s %-8s %s\n' "$name" "$v_wo" "$v_w" "$(echo "$out_w" | tail -1 | cut -c1-100)"
    printf '%-40s %s\n' "" "$(echo "$out_wo" | tail -1 | cut -c1-100)"
done
rm -f "$SBX_HOME/$LABEL.plist"

# Seatbelt denials of this sandbox, from the persisted log (capped; never an
# unbounded stream to disk: a looping process can log millions of denials).
sleep 2
echo
echo "Seatbelt denials tagged $SBX_TAG since $start (distinct):"
/usr/bin/log show --style compact --start "$start" \
    --predicate "(sender == \"Sandbox\" OR subsystem == \"com.apple.sandbox.reporting\") AND eventMessage CONTAINS \"$SBX_TAG\"" 2>/dev/null \
    | grep 'Sandbox: ' | grep -oE 'deny\([0-9]+\) [a-z*-]+ [^ "]+' | head -n 2000 \
    | sed -E 's/^deny\([0-9]+\)/deny/' | sort | uniq -c | sort -rn | head -40
