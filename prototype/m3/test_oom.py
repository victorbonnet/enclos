"""Harmless per-child O_TRUNC regression; never changes a host service."""
import json
import os
import subprocess
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inside


class OomTest(unittest.TestCase):
    def test_proc_truncate(self):
        abi, _ = inside.landlock_abi()
        if abi is None or abi < 3:
            self.skipTest("Landlock ABI >=3 required")
        rules = dict(read=["/"], execute=["/usr", "/bin"], write=[],
                     devices=[], proc_write=["/proc"], scoped=[])
        for legacy in [True, False]:
            code = "import sys; sys.path.insert(0, sys.argv[1]); import inside; import json, os; "
            if legacy:
                code += "inside.TRUNCATE = 0; "
            code += "inside.apply_landlock(json.loads(sys.argv[2])); os.execl('/bin/sh', 'sh', '-c', 'echo 0 > /proc/self/oom_score_adj')"
            result = subprocess.run([sys.executable, "-I", "-c", code,
                                     os.path.dirname(__file__), json.dumps(rules)],
                                    capture_output=True, text=True)
            print(f"proc O_TRUNC legacy={legacy}: exit={result.returncode} {result.stderr.strip()}")
            self.assertEqual(result.returncode == 0, not legacy, result.stderr)


if __name__ == "__main__":
    unittest.main()
