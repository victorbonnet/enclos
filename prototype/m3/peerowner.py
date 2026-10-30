"""Who owns the client end of a connection to the host's listener (M3-03): read
from the kernel's socket tables, /proc/net/tcp and /proc/net/tcp6, where each
socket's row names its owner's uid. Pure but for read_tables: test_peerowner.py
tests it on fixture text. A dual-stack client's IPv4 connection is in tcp6, as
a v4-mapped address, so both tables are read.

The rule fails closed: a connection is served only when one established client
row names exactly the expected uid. No row (the client has gone), a row in any
other state (a TIME_WAIT row has no owner) or an unreadable table is refused.
"""

import socket
import struct

ESTABLISHED = "01"
TABLES = ("/proc/net/tcp", "/proc/net/tcp6")
MAPPED = "::ffff:"


def address(field):
    """A table's HEXADDR:HEXPORT as (address text, port), in this host's byte
    order, as the kernel prints it. A v4-mapped address reads as IPv4."""
    host, port = field.split(":")
    words = [int(host[i:i + 8], 16) for i in range(0, len(host), 8)]
    raw = struct.pack(f"={len(words)}I", *words)
    if len(raw) == 4:
        text = socket.inet_ntop(socket.AF_INET, raw)
    else:
        text = socket.inet_ntop(socket.AF_INET6, raw)
        if text.startswith(MAPPED):
            text = text[len(MAPPED):]
    return text, int(port, 16)


def rows(text):
    """(local, remote, state, uid) for each well-formed row; a bad row is left
    out, which can only leave a connection unknown."""
    found = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        try:
            found.append((address(fields[1]), address(fields[2]), fields[3], int(fields[7])))
        except (IndexError, ValueError, OSError, struct.error):
            continue
    return found


def owner(tables, client, server):
    """The uid of the socket at `client` connected to `server`, each an
    (address, port), or None unless the tables' texts give exactly one."""
    uids = {uid for text in tables for local, remote, state, uid in rows(text)
            if local == client and remote == server and state == ESTABLISHED}
    return uids.pop() if len(uids) == 1 else None


def allowed(found, uid):
    return found is not None and found == uid


def read_tables(paths=TABLES):
    """The tables' texts. One that cannot be read is left out: tcp6 may not
    exist, and a missing tcp leaves the client unknown, so it is refused."""
    texts = []
    for path in paths:
        try:
            with open(path) as f:
                texts.append(f.read())
        except OSError:
            pass
    return texts
