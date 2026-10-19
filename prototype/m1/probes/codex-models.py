"""List the Codex models the logged-in ChatGPT account may use (run in the sandbox).

Uses Hermes's own resolver read-only (no refresh, no auth-store write) and its
live discovery. Prints model ids only, never the token.
    ./sbx.sh -- <hermes venv python> -I probes/codex-models.py <hermes-agent dir>
"""

import sys

sys.path.insert(0, sys.argv[1])
from hermes_cli.auth_codex import resolve_codex_runtime_credentials  # noqa: E402
from hermes_cli.codex_models import _fetch_models_from_api  # noqa: E402

creds = resolve_codex_runtime_credentials(read_only=True)
print("base_url:", creds["base_url"], "source:", creds["source"])
for model in _fetch_models_from_api(creds["api_key"], creds["base_url"]):
    print(model)
