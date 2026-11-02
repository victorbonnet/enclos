"""What dashboard-chat-check.sh's control pair reads as (M3-03). The sentence on
the cause comes from the backend rows alone; a missing answer is said apart,
since counting words on a terminal in a window shows no cause.

    python3 -I chat-reading.py VERDICTS.tsv

Prints the reading of the backend rows, then that of the answer rows.
"""

import importlib.util
import os
import sys

BACKEND = ("no loopback denial in the proxy log while the terminal is used",
           "the Chat tab's backend connection is established")
ANSWERS = ("a prompt typed on /api/pty gets an answer in the terminal",
           "a prompt typed in the Chat tab gets an answer")
ROUNDS = {"as-is": "as it is", "fixed": "with NO_PROXY for loopback"}


def verdicts(lines, label, names):
    """The verdicts of that round's named rows, in the order found."""
    wanted = {f"{label}: {name}" for name in names}
    return [fields[1] for fields in (line.split("\t") for line in lines) if fields[0] in wanted]


def backend(lines):
    pairs = [verdicts(lines, label, BACKEND) for label in ROUNDS]
    if any(len(found) != len(BACKEND) for found in pairs):
        return "A round did not reach the backend rows: read them."
    refused, fixed_refused = ("FAIL" in found for found in pairs)
    if fixed_refused:
        return "With NO_PROXY for loopback the terminal still does not reach its backend: read the rows."
    if refused:
        return ("The session's proxy environment keeps the terminal from its backend: as it is the proxy "
                "refuses the connection, and with NO_PROXY for loopback the connection is established.")
    return "Both rounds reach the backend: this run does not reproduce the failure, so the fix is not shown to matter."


def answers(lines, seconds):
    silent = [text for label, text in ROUNDS.items() if "pass" not in verdicts(lines, label, ANSWERS)]
    if not silent:
        return "A typed prompt got an answer in both rounds."
    return f"No answer within the {seconds} s window {' or '.join(silent)}; cause not shown."


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    spec = importlib.util.spec_from_file_location("host_client", f"{here}/host-client.py")
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    with open(sys.argv[1]) as f:
        lines = f.read().splitlines()
    print(backend(lines))
    print(answers(lines, client.ANSWER_SECONDS))


if __name__ == "__main__":
    main()
