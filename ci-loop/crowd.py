"""Holds N listeners on 127.0.0.1, on ports the system chooses, until killed:
a crowded loopback, as when many tests listen at once. (Throwaway, to drop.)
usage: python3 -I crowd.py [n]
"""
import signal
import socket
import sys

held = []
for _ in range(int(sys.argv[1]) if len(sys.argv) > 1 else 3000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen()
    held.append(s)
print(f"holding {len(held)} listeners on 127.0.0.1", flush=True)
signal.pause()
