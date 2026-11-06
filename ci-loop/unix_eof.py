"""Does a reader blocked in recv() on a Unix stream socket always see its
peer's shutdown(SHUT_WR)? Each round: a connected pair, a reader thread
blocked in recv() (with SO_RCVTIMEO, as Rust's set_read_timeout sets, or
without), a writer that sends a few bytes and then shuts down its writing.
A reader still blocked STALL seconds after the shutdown missed the end of
input; its socket's state is then printed.

usage: python3 -I unix_eof.py [pairs at once] [rounds] [timeout|none] [bytes] [unix|tcp] [shutdown|settled|close]
"""
import socket
import struct
import subprocess
import sys
import threading
import time

PAIRS = int(sys.argv[1]) if len(sys.argv) > 1 else 32
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 200
TIMEOUT = (sys.argv[3] if len(sys.argv) > 3 else "timeout") == "timeout"
BYTES = int(sys.argv[4]) if len(sys.argv) > 4 else 7
STALL = 5.0
READ_TIMEOUT = 30


KIND = sys.argv[5] if len(sys.argv) > 5 else "unix"
# How the writer ends: "shutdown" right after its bytes, "settled" 5 ms
# after them (the reader asleep again by then), or "close".
END = sys.argv[6] if len(sys.argv) > 6 else "shutdown"


def pair():
    """A connected pair: a Unix socketpair, or TCP over 127.0.0.1."""
    if KIND == "unix":
        return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        writer = socket.create_connection(listener.getsockname())
        reader, _ = listener.accept()
        return writer, reader


def one(results, i):
    writer, reader = pair()
    if TIMEOUT:
        reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("qq", READ_TIMEOUT, 0))
    got = []
    ended = threading.Event()
    outcome = {}

    def read():
        try:
            while True:
                chunk = reader.recv(65536)
                if not chunk:
                    outcome["end"] = "eof"
                    break
                got.append(len(chunk))
        except OSError as e:
            outcome["end"] = f"error {e.errno}"
            if e.errno == 35:
                # Asked again, after the timeout.
                try:
                    outcome["end"] += f", and a second recv() gave {reader.recv(65536)!r} at once"
                except OSError as again:
                    outcome["end"] += f", and a second recv() failed with {again.errno}"
        ended.set()

    t = threading.Thread(target=read, daemon=True)
    t.start()
    writer.sendall(b"x" * BYTES)
    if END == "settled":
        time.sleep(0.005)
    if END == "close":
        writer.close()
    else:
        writer.shutdown(socket.SHUT_WR)
    shut = time.monotonic()
    if not ended.wait(STALL):
        pid = __import__("os").getpid()
        if sys.platform == "linux":
            look = f"ss -xpn | grep 'pid={pid},'"
        else:
            look = f"netstat -anv -f {'unix' if KIND == 'unix' else 'inet'} | awk 'NR==2 || index($0, \":{pid} \")'"
        state = subprocess.run(["sh", "-c", look], capture_output=True, text=True).stdout
        results.append((i, "STALL", sum(got), state))
        if not ended.wait(READ_TIMEOUT + 5):
            outcome["end"] = f"nothing after {READ_TIMEOUT + 5 + STALL:.0f}s (left blocked)"
            results.append((i, outcome["end"], sum(got), ""))
            return
        results.append((i, f"then {outcome.get('end')} after {time.monotonic() - shut:.1f}s", sum(got), ""))
    elif outcome.get("end") != "eof" or sum(got) != BYTES:
        results.append((i, outcome.get("end"), sum(got), ""))
    t.join()
    writer.close()
    reader.close()


results = []
start = time.monotonic()
for r in range(ROUNDS):
    threads = [threading.Thread(target=one, args=(results, r * PAIRS + p)) for p in range(PAIRS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if results:
        break
print(f"{KIND}, {END}, {'SO_RCVTIMEO' if TIMEOUT else 'no timeout'}, {BYTES} bytes: "
      f"{len([x for x in results if x[1] == 'STALL'])} stalls in {r + 1} rounds of {PAIRS} pairs "
      f"({time.monotonic() - start:.0f}s)")
for i, what, n, state in results:
    print(i, what, n)
    if state:
        print(state)
