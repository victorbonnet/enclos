"""Expand dynamic home masks at session launch, never at snapshot compile."""
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile import hide


def arguments(compiled):
    args = []
    remount = []
    for arg in compiled["bwrap"]:
        if arg == "@HOME_MASK@":
            mask = compiled["home_mask"]
            hide(mask["home"], set(mask["denied"]), args, remount)
        else:
            args.append(arg)
    # Mount construction precedes sealing the masks. Validated grants never
    # cover a deny, so no workspace is one of these remount targets.
    for folder in remount:
        args += ["--remount-ro", folder]
    return args


if __name__ == "__main__":
    sys.stdout.write("".join(arg + "\0" for arg in arguments(json.load(open(sys.argv[1])))))
