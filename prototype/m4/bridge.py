#!/usr/bin/env python3
"""Prototype bridge (enclos prototype/m4), run on the host. Not enclos code.

Connects to an agent's socket in the sandbox home and prints what the agent
sends. In `chat` mode, each line typed is sent to the agent in one
conversation.

  bridge.py chat SOCKET [--conversation ID] [--person ID]
  bridge.py listen SOCKET          # cron deliveries, any conversation

Standard library only.
"""

import argparse
import json
import socket
import sys
import threading
import uuid


def connect(path: str) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as e:
        sys.exit(f"cannot connect to {path}: {e}")
    return sock


def print_incoming(sock: socket.socket) -> None:
    for line in sock.makefile("r", encoding="utf-8"):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            print(f"(not JSON) {line.rstrip()}", flush=True)
            continue
        if msg.get("type") == "message.out":
            print(f"\n[{msg.get('conversation')}] {msg.get('text')}", flush=True)
        else:
            print(f"\n{msg}", flush=True)
    print("\n(agent closed the socket)", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    chat = sub.add_parser("chat")
    chat.add_argument("socket")
    chat.add_argument("--conversation", default=None, help="default: a new one")
    chat.add_argument("--person", default="owner")
    listen = sub.add_parser("listen")
    listen.add_argument("socket")
    args = parser.parse_args()

    sock = connect(args.socket)
    if args.mode == "listen":
        print_incoming(sock)
        return

    conversation = args.conversation or uuid.uuid4().hex[:12]
    print(f"conversation {conversation}; Ctrl-D to quit", flush=True)
    threading.Thread(target=print_incoming, args=(sock,), daemon=True).start()
    for line in sys.stdin:
        text = line.strip()
        if not text:
            continue
        msg = {"type": "message.in", "id": uuid.uuid4().hex, "conversation": conversation,
               "person": args.person, "text": text}
        sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
    sock.close()


if __name__ == "__main__":
    main()
