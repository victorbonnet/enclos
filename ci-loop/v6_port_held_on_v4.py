"""How often the system gives [::1] a port that 127.0.0.1 already holds.

Holds HELD listeners on 127.0.0.1 (ports the system chooses), then binds
[::1] on port 0 TRIES times and counts the ports already held on 127.0.0.1.
usage: python3 -I v6_port_held_on_v4.py [held] [tries]
"""
import socket
import sys

held_n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
tries = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
held = []
for _ in range(held_n):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen()
    held.append(s)
v4 = {s.getsockname()[1] for s in held}
hits = 0
for _ in range(tries):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(("::1", 0))
    hits += s.getsockname()[1] in v4
    s.close()
print(f"{sys.platform}: {held_n} listeners on 127.0.0.1; "
      f"{hits} of {tries} ports given to [::1] were among them "
      f"({100 * hits / tries:.2f}%, expected about {100 * held_n / (len(range(32768, 61000)) // 2):.2f}% on Linux)")
