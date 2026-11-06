"""Every workflow file is valid YAML. GitHub names a run after the file's path
and runs none of its jobs when the file does not parse (a plain `run:` value
holding a colon and a space did that), and the other checks stay green, so
nothing else notices. Pure: reads the repository's workflow files only."""
import glob
import os
import unittest

try:
    import yaml
except ImportError:  # a developer's machine; the runners have PyYAML
    yaml = None

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


class WorkflowsParse(unittest.TestCase):
    def test_every_workflow_file_is_valid_yaml(self):
        if yaml is None:
            if os.environ.get("GITHUB_ACTIONS"):
                self.fail("PyYAML is missing on a runner")
            self.skipTest("PyYAML is not installed here")
        files = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))
        self.assertTrue(files)
        for path in files:
            with open(path) as f:
                try:
                    doc = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    self.fail(f"{os.path.relpath(path, ROOT)}: {e}")
            self.assertIn("jobs", doc, path)


if __name__ == "__main__":
    unittest.main()
