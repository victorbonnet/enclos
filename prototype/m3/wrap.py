"""The prototype's wrap step (a draft of what M3-13 builds): at each session's
start, turns the compiled policy, which is pure and cached, into bubblewrap's
arguments, from what the host holds at that moment. read_host() reads the
host; arguments() only uses what it is given.

    python3 -I wrap.py compiled.json   # the arguments, each ending in NUL
"""
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile import under


def grant_paths(mask):
    return [g["path"] for g in mask["grants"]]


def hidden_paths(mask, resolved):
    """The paths the home's folders leave out: each deny entry and, where a
    link takes it elsewhere, what it resolves to. Seatbelt compiles the resolved
    path, so the same policy hides the target on both (design §15). A target a
    grant holds is masked there instead. One neither under the home nor in a
    grant stays readable through the broad read, so it stops the session until
    §15 decides that case. The home is given with no link in its path."""
    roots = [resolved[g] for g in grant_paths(mask)]
    hidden = set(mask["denied"])
    for d in mask["denied"]:
        target = resolved[d]
        if any(under(target, root) for root in roots):
            continue
        if target == mask["home"] or not under(target, mask["home"]):
            sys.exit(f"wrap.py: deny entry {d} resolves to {target}, which cannot be hidden")
        hidden.add(target)
    return hidden


def masked_in_grants(mask, resolved):
    """(path, writable) for each denied path a grant holds, under the grant's
    own name for it. Paths compare resolved: a grant may be reached through a
    link."""
    for grant in mask["grants"]:
        root = resolved[grant["path"]]
        for d in mask["denied"]:
            if under(resolved[d], root):
                rel = os.path.relpath(resolved[d], root)
                yield os.path.normpath(os.path.join(grant["path"], rel)), grant["write"]


def read_host(compiled):
    """What this session's mounts depend on. `entries`: each real folder from
    the home down that holds a hidden path (hidden_paths), stopping at a grant
    whichever name it is reached by, its names mapped to a link's target or None. `resolved`: each denied path and
    grant with links resolved. `kinds`: what is now at each path masked in a grant, "dir",
    "file" or None. A folder that went away lists nothing; one that cannot be
    read stops the session, since what it holds cannot be hidden."""
    mask = compiled["home_mask"]
    grants = grant_paths(mask)
    resolved = {p: os.path.realpath(p) for p in mask["denied"] + grants}
    hidden = hidden_paths(mask, resolved)
    roots = [resolved[g] for g in grants]
    entries = {}

    def walk(folder):
        if any(under(os.path.realpath(folder), root) for root in roots):
            return  # the grant's bind replaces it, whichever name it goes by
        try:
            names = os.listdir(folder)
        except (FileNotFoundError, NotADirectoryError):
            return
        found = entries[folder] = {}
        for name in names:
            path = os.path.join(folder, name)
            try:
                found[name] = os.readlink(path)
            except OSError:
                found[name] = None
                if any(under(d, path) and d != path for d in hidden):
                    walk(path)

    walk(mask["home"])
    kinds = {}
    for path, _ in masked_in_grants(mask, resolved):
        kinds[path] = "dir" if os.path.isdir(path) else "file" if os.path.lexists(path) else None
    return {"entries": entries, "resolved": resolved, "kinds": kinds}


def hide(folder, denied, entries, args, remount):
    """Mount an empty tmpfs on `folder`, then bind back every entry that is
    neither denied nor on the way to a denied path. A grant is bound whole
    later, so what it holds is masked after that bind, not here. --ro-bind-try:
    an entry may go between the listing and bubblewrap's start."""
    args += ["--tmpfs", folder]
    remount.append(folder)
    for name, link in sorted(entries.get(folder, {}).items()):
        path = os.path.join(folder, name)
        if path in denied:
            continue
        if link is not None:
            args += ["--symlink", link, path]
        elif path in entries:
            hide(path, denied, entries, args, remount)
        else:
            args += ["--ro-bind-try", path, path]


def mask_in_grants(mask, listing, args, remount):
    """Mask each denied path a grant holds, after the grant's bind (design §5):
    a read-only empty tmpfs for a folder, the sandbox's read-only empty file
    for a file. Not /dev/null: bubblewrap's binds are nodev, so it could not
    be opened, and a device on a read-only mount still takes writes. A path
    that does not exist gets the tmpfs in a writable grant, or the sandbox
    could make it there; a read-only grant cannot take a mount point, and the
    sandbox cannot make the path."""
    for path, writable in masked_in_grants(mask, listing["resolved"]):
        kind = listing["kinds"].get(path)
        if kind == "dir" or kind is None and writable:
            args += ["--tmpfs", path]
            remount.append(path)
        elif kind == "file":
            args += ["--ro-bind", mask["empty_file"], path]


def arguments(compiled, listing):
    """Bubblewrap's arguments for one session, from read_host()'s listing."""
    mask = compiled["home_mask"]
    grants = grant_paths(mask)
    resolved = listing["resolved"]
    for g in grants:
        for d in mask["denied"]:
            if under(resolved[g], resolved[d]):
                sys.exit(f"wrap.py: grant {g} is at or inside denied path {d}")
    args = []
    remount = []
    for arg in compiled["bwrap"]:
        if arg == "@HOME_MASK@":
            if mask["home"] in listing["entries"]:
                hide(mask["home"], hidden_paths(mask, resolved), listing["entries"], args, remount)
        elif arg == "@GRANT_MASK@":
            mask_in_grants(mask, listing, args, remount)
        else:
            args.append(arg)
    # The tmpfs that hide denied paths were writable while bubblewrap made
    # mount points in them; nothing may write there afterwards. A grant's bind
    # replaces none of these: read_host() lists nothing a grant holds.
    for folder in remount:
        args += ["--remount-ro", folder]
    return args


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        policy = json.load(f)
    sys.stdout.write("".join(arg + "\0" for arg in arguments(policy, read_host(policy))))
