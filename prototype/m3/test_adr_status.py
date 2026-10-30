"""ADRs 0037 to 0040 stay proposed: the owner accepts them, not a change that
happens to edit them. Reads each ADR's front matter, by its number so a retitled
file still counts. Pure, so it runs anywhere:

    python3 -I prototype/m3/test_adr_status.py

CI runs it through test_nsjoin.py, which imports this class.
"""

import glob
import os
import unittest

ADR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "adr")
PROPOSED = ("0037", "0038", "0039", "0040")


def status(number, folder=ADR):
    """The `status:` of the one ADR with that number, or None."""
    paths = glob.glob(os.path.join(folder, f"{number}-*.md"))
    if len(paths) != 1:
        return None
    with open(paths[0]) as f:
        head = f.read().split("---")
    if len(head) < 3:
        return None
    fields = dict(line.split(":", 1) for line in head[1].splitlines() if ":" in line)
    return fields.get("status", "").strip() or None


class StayProposed(unittest.TestCase):
    def test_each_stays_proposed(self):
        for number in PROPOSED:
            self.assertEqual(status(number), "proposed", number)


if __name__ == "__main__":
    unittest.main()
