"""The plugin's agent for a call outside the app, against a real Hermes.

ENCLOS_HERMES_SOURCE=/path/to/hermes-agent python3 -m unittest discover ...
The plugin names a call's agent with Hermes's own helpers,
`profile_name_for_home(get_hermes_home())`, and sends it on the connection
whose socket is `<agent>.sock` (enclos's `Layout::agent_app_socket`): the two
names must be the same, for the built-in agent and for a profile.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class RealHermesNamesTheAgent(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / ".hermes"
        (self.root / "profiles" / "scout").mkdir(parents=True)
        (self.root / "profiles" / "scout" / "config.yaml").write_text("")
        sys.path.insert(0, os.environ["ENCLOS_HERMES_SOURCE"])
        self.addCleanup(sys.path.remove, os.environ["ENCLOS_HERMES_SOURCE"])

    def agent(self, hermes_home: Path) -> str:
        env = {"HOME": str(self.home), "HERMES_HOME": str(hermes_home)}
        with patch.dict(os.environ, env):
            sys.modules.pop("hermes_constants", None)
            from hermes_constants import get_hermes_home, profile_name_for_home
            return profile_name_for_home(get_hermes_home())

    def test_the_built_in_agent_and_a_profile_are_named_as_their_sockets(self):
        # Their sockets: `.enclos-app/default.sock` and `.enclos-app/scout.sock`.
        self.assertEqual(self.agent(self.root), Path("default.sock").stem)
        self.assertEqual(self.agent(self.root / "profiles" / "scout"), Path("scout.sock").stem)


if __name__ == "__main__":
    unittest.main()
