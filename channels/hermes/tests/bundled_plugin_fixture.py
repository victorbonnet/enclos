"""Import only emitted plugin files, with test-owned gateway interfaces."""
import sys
from pathlib import Path
from types import ModuleType

sys.modules['gateway.run'] = ModuleType('gateway.run')
sys.path.insert(0, str(Path(__file__).parent))
from test_adapter import _hermes_stand_ins
sys.modules.update(_hermes_stand_ins())
# The helper imports repository modules at module scope; discard them and
# remove that search path so omitted emitted files cannot fall back to source.
for name in list(sys.modules):
    if name == 'enclos' or name.startswith('enclos.'):
        del sys.modules[name]
sys.path.remove(str(Path(__file__).parent / '..'))
sys.path.insert(0, sys.argv[1])
from enclos import adapter, incoming, image_eligibility
for module in (adapter, incoming, image_eligibility):
    assert Path(module.__file__).is_relative_to(Path(sys.argv[1]))
assert not image_eligibility.available(object())
