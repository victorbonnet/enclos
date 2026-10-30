"""The little of RFC 6455 the M3-03 host-path checks need, on the standard
library alone: the handshake's accept key and one frame at a time. Pure:
test_host_path.py tests it anywhere.
"""

import base64
import hashlib
import os
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TEXT, CLOSE, PING, PONG = 1, 8, 9, 10


def accept_key(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def new_key():
    return base64.b64encode(os.urandom(16)).decode()


def encode(payload, opcode=TEXT, mask=None):
    """One final frame. A client passes a four-byte mask, a server none."""
    head = bytes([0x80 | opcode])
    bit = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        head += bytes([bit | n])
    elif n < 65536:
        head += bytes([bit | 126]) + struct.pack(">H", n)
    else:
        head += bytes([bit | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + payload
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def decode(buf):
    """The first frame in buf as (opcode, payload, bytes used), or None when
    buf does not hold a whole frame yet."""
    if len(buf) < 2:
        return None
    opcode, masked, n = buf[0] & 0x0F, buf[1] & 0x80, buf[1] & 0x7F
    at = 2
    if n >= 126:
        size = 2 if n == 126 else 8
        if len(buf) < at + size:
            return None
        n = int.from_bytes(buf[at:at + size], "big")
        at += size
    mask = b""
    if masked:
        if len(buf) < at + 4:
            return None
        mask = buf[at:at + 4]
        at += 4
    if len(buf) < at + n:
        return None
    body = buf[at:at + n]
    if masked:
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
    return opcode, body, at + n
