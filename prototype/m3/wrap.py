"""Expand dynamic home masks at session launch, never at snapshot compile."""
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile import hide, under


def mask_in_grants(mask, args, remount):
    """Mask each denied path a grant holds, after the grant's bind (design §5).
    A path that does not exist gets a mount point in a writable grant, or the
    sandbox could make it there; a read-only grant cannot make one, and the
    sandbox cannot make the path. Paths compare resolved, as a grant may be
    reached through a link."""
    for grant in mask["grants"]:
        root = os.path.realpath(grant["path"])
        for d in mask["denied"]:
            deny = os.path.realpath(d)
            if not under(deny, root):
                continue
            path = os.path.normpath(os.path.join(grant["path"], os.path.relpath(deny, root)))
            if os.path.isdir(path) or not os.path.lexists(path) and grant["write"]:
                args += ["--tmpfs", path]
                remount.append(path)
            elif os.path.lexists(path):
                args += ["--ro-bind", "/dev/null", path]


def arguments(compiled):
    args = []
    remount = []
    mask = compiled["home_mask"]
    grants = {g["path"] for g in mask["grants"]}
    for arg in compiled["bwrap"]:
        if arg == "@HOME_MASK@":
            hide(mask["home"], set(mask["denied"]), grants, args, remount)
        elif arg == "@GRANT_MASK@":
            mask_in_grants(mask, args, remount)
        else:
            args.append(arg)
    # The tmpfs that hide denied paths were writable while bubblewrap made
    # mount points in them; nothing may write there afterwards. Only those:
    # a tmpfs at a grant's own path is gone under the grant's bind.
    for folder in remount:
        if folder not in grants:
            args += ["--remount-ro", folder]
    return args


if __name__ == "__main__":
    sys.stdout.write("".join(arg + "\0" for arg in arguments(json.load(open(sys.argv[1])))))
