"""What Hermes's own client code does to find its gateway (M3-03), run with
Hermes's interpreter in a session of the sandbox: it lists the functions of
`hermes_cli.gateway_client`, then calls those whose names say they look for
a gateway and that need no argument, and prints what each returned. Names
that say they start, stop or signal something are never called.

    <hermes's python> -I hermes-discover.py <hermes source folder>
"""

import inspect
import re
import signal
import sys

sys.path.insert(0, sys.argv[1])
try:
    import hermes_cli.gateway_client as client
except Exception as e:  # noqa: BLE001 - reported, the check goes on
    print(f"import hermes_cli.gateway_client: {e!r}")
    sys.exit(0)

LOOKS = re.compile(r"find|discover|locate|running|status|probe|resolve|endpoint|alive|read|load|info")
ACTS = re.compile(r"start|spawn|ensure|launch|kill|stop|signal|restart|write|save|remove|delete|connect|send")


def alarm(_sig, _frame):
    raise TimeoutError("15 s")


signal.signal(signal.SIGALRM, alarm)
for name, fn in inspect.getmembers(client, inspect.isfunction):
    if fn.__module__ != client.__name__:
        continue
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        continue
    print(f"def {name}{sig}")
    required = [p for p in sig.parameters.values()
                if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    if required or not LOOKS.search(name) or ACTS.search(name):
        continue
    signal.alarm(15)
    try:
        print(f"  -> {fn()!r}"[:400])
    except BaseException as e:  # noqa: BLE001
        print(f"  -> raised {e!r}"[:400])
    finally:
        signal.alarm(0)
