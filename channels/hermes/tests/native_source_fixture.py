"""Fail closed against ambient removed APIs in a selected current checkout."""
import importlib.abc
import importlib.util
from pathlib import Path
import os
import sys

source = Path(os.environ.get("ENCLOS_HERMES_SOURCE", Path.home() / ".hermes/hermes-agent")).resolve()
current = (source / "persistence_assembly.py").exists()
class RemovedLegacy(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if current and fullname == "hermes_state_runtime":
            raise ModuleNotFoundError("removed legacy API forbidden in selected current source")
if current:
    sys.meta_path.insert(0, RemovedLegacy())

def verify():
    if current:
        assert "hermes_state_runtime" not in sys.modules
    for name, module in tuple(sys.modules.items()):
        if name == "gateway.run":
            continue  # deliberately test-owned fail-closed sentinel
        if (name.startswith(("gateway.", "persistence.")) or
                name in ("persistence_assembly", "hermes_state", "hermes_state_runtime",
                         "agent.image_routing")) and getattr(module, "__file__", None):
            assert Path(module.__file__).resolve().is_relative_to(source), (name, module.__file__, source)
