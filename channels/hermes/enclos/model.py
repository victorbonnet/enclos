"""The agent's model, read and changed from the app (`model.request`).

Hermes keeps it: its own inventory lists the providers and their models,
and its own `/model --global` path (`switch_model`, then
`persist_model_selection`) checks and saves a choice in the agent's
profile `config.yaml`. The gateway reads that file again for each turn, so
a saved choice applies to the agent's next turn without a restart.
"""
import hashlib
import inspect
import json
import logging
import threading
import time
from pathlib import Path

from . import visible

logger = logging.getLogger(__name__)

MAX_PROVIDERS = 100
MAX_MODELS = 300
MAX_ID_BYTES = 200
MAX_LABEL_BYTES = 200
# How long one reading of the inventory serves `options` and `models`.
INVENTORY_SECONDS = 60


class ModelError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _short(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _id(value):
    """A provider's or model's id the protocol can carry, else None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value.encode("utf-8")) > MAX_ID_BYTES:
        return None
    if visible.has_hidden(value):
        return None
    return value


def _label(value, fallback):
    if isinstance(value, str) and value.strip() and not visible.has_hidden(value):
        return _short(value.strip(), MAX_LABEL_BYTES)
    return fallback


def validate_request(message):
    action = message.get("action")
    if action == "options":
        return
    if action == "models":
        if _id(message.get("provider")) is None:
            raise ModelError("bad_message", "provider is not an id")
        return
    if action == "set":
        for key in ("provider", "model", "revision"):
            if _id(message.get(key)) is None:
                raise ModelError("bad_message", f"{key} is not an id")
        return
    raise ModelError("bad_message", "unknown model action")


class Manager:
    """One agent's model. `functions` replaces Hermes's own, in tests."""

    def __init__(self, agent, home=None, functions=None):
        self.agent = agent
        self.unavailable = None
        self._lock = threading.Lock()
        self._inventory = None
        try:
            if functions is None:
                functions = self._hermes()
            self.f = functions
            self.home = Path(home or self.f["home"]()).resolve()
        except Exception as error:
            self.f = None
            self.unavailable = f"{type(error).__name__}: {error}"
            logger.warning("Choosing the model from the app is off for this Hermes: %s", self.unavailable)

    @staticmethod
    def _hermes():
        import hermes_constants
        from hermes_cli import config, inventory, model_switch
        needed = {
            "config": getattr(config, "load_config", None),
            "home": getattr(hermes_constants, "get_hermes_home", None),
            "scope": getattr(hermes_constants, "set_hermes_home_override", None),
            "unscope": getattr(hermes_constants, "reset_hermes_home_override", None),
            "context": getattr(inventory, "load_picker_context", None),
            "payload": getattr(inventory, "build_models_payload", None),
            "switch": getattr(model_switch, "switch_model", None),
            "persist": getattr(model_switch, "persist_model_selection", None),
        }
        missing = [key for key, value in needed.items() if not callable(value)]
        if missing:
            raise LookupError(f"Hermes has no {', '.join(missing)}")
        switch = inspect.signature(needed["switch"]).parameters
        if not {"raw_input", "explicit_provider", "is_global"}.issubset(switch):
            raise LookupError("switch_model takes other parameters")
        return needed

    @property
    def available(self):
        return self.f is not None

    def _scoped(self, call):
        token = self.f["scope"](str(self.home))
        try:
            return call()
        finally:
            self.f["unscope"](token)

    # What the agent's settings say now

    def _config(self):
        loaded = self._scoped(self.f["config"])
        return loaded if isinstance(loaded, dict) else {}

    def _current(self, config):
        block = config.get("model")
        if isinstance(block, dict):
            model = _id(block.get("default") or block.get("model") or block.get("name"))
            provider = _id(block.get("provider"))
        else:
            model, provider = _id(block), None
        if model is None:
            return None
        return {"model": model, **({"provider": provider} if provider else {})}

    @staticmethod
    def _revision(config):
        block = json.dumps(config.get("model"), sort_keys=True, default=str)
        return hashlib.sha256(block.encode("utf-8")).hexdigest()[:32]

    # Hermes's inventory

    def _payload(self, fresh=False):
        now = time.monotonic()
        if not fresh and self._inventory and now - self._inventory[0] < INVENTORY_SECONDS:
            return self._inventory[1]
        build = self.f["payload"]
        parameters = inspect.signature(build).parameters
        flags = {"include_unconfigured": True, "non_blocking_catalogs": True,
                 "probe_custom_providers": False, "probe_current_custom_provider": False,
                 "max_models": MAX_MODELS + 1}
        payload = self._scoped(lambda: build(
            self.f["context"](), **{k: v for k, v in flags.items() if k in parameters}))
        if not isinstance(payload, dict):
            payload = {}
        self._inventory = (now, payload)
        return payload

    def _rows(self, payload):
        rows = {}
        for row in payload.get("providers") or []:
            if not isinstance(row, dict):
                continue
            slug = _id(row.get("slug"))
            if slug is None or slug in rows:
                continue
            rows[slug] = row
        return rows

    @staticmethod
    def _usable(row):
        # Hermes's inventory adds providers with no credentials as setup
        # skeletons (`source: canonical`), and keeps the current one
        # without credentials marked `authenticated: false`.
        return row.get("authenticated") is not False and row.get("source") != "canonical"

    def _setup(self, row):
        key = _id(row.get("key_env"))
        how = f"run `hermes -p {self.agent} model` in an `enclos connect` session on the host"
        if key:
            return f"Set it up on the host: grant {key} to the sandbox, or {how}."
        return f"Set it up on the host: {how}."

    @staticmethod
    def _models(row):
        models = []
        for item in row.get("models") or []:
            identifier = _id(item.get("id") if isinstance(item, dict) else item)
            if identifier is None or any(m["id"] == identifier for m in models):
                continue
            name = item.get("name") or item.get("label") if isinstance(item, dict) else None
            models.append({"id": identifier, "label": _label(name, identifier)})
        total = row.get("total_models")
        limited = len(models) > MAX_MODELS or (isinstance(total, int) and total > len(models))
        return models[:MAX_MODELS], limited

    # The requests

    def handle(self, message):
        validate_request(message)
        with self._lock:
            try:
                return self._handle(message)
            except ModelError:
                raise
            except Exception:
                logger.warning("The agent's model request failed", exc_info=True)
                raise ModelError("unknown", "The outcome is unknown: open the agent's model again before retrying.") from None

    def _handle(self, message):
        action = message["action"]
        if action == "options":
            config = self._config()
            rows = self._rows(self._payload(fresh=True))
            providers = []
            for slug, row in list(rows.items())[:MAX_PROVIDERS]:
                usable = self._usable(row)
                provider = {"id": slug, "label": _label(row.get("name"), slug), "usable": usable}
                if not usable:
                    provider["setup"] = self._setup(row)
                providers.append(provider)
            current = self._current(config)
            return {"result": "options", **({"current": current} if current else {}),
                    "revision": self._revision(config), "applies": "live",
                    "providers": providers, "custom_models": True}
        if action == "models":
            row = self._rows(self._payload()).get(message["provider"])
            if row is None:
                raise ModelError("not_found", "This runtime does not list that provider.")
            models, limited = self._models(row)
            return {"result": "models", "provider": message["provider"], "models": models, "limited": limited}
        return self._set(message["provider"], message["model"], message["revision"])

    def _set(self, provider, model, revision):
        config = self._config()
        if self._revision(config) != revision:
            raise ModelError("conflict", "The agent's model changed since it was read. Open it again.")
        row = self._rows(self._payload()).get(provider)
        if row is None:
            raise ModelError("not_found", "This runtime does not list that provider.")
        if not self._usable(row):
            raise ModelError("not_allowed", f"The agent cannot use {provider} yet. {self._setup(row)}")
        previous = self._current(config)

        def switch():
            context = self.f["context"]()
            arguments = {
                "raw_input": model, "explicit_provider": provider, "is_global": True,
                "current_provider": getattr(context, "current_provider", "") or "",
                "current_model": getattr(context, "current_model", "") or "",
                "current_base_url": getattr(context, "current_base_url", "") or "",
                "current_api_key": "",
                "user_providers": getattr(context, "user_providers", None),
                "custom_providers": getattr(context, "custom_providers", None),
            }
            parameters = inspect.signature(self.f["switch"]).parameters
            result = self.f["switch"](**{k: v for k, v in arguments.items() if k in parameters})
            if not getattr(result, "success", False):
                return result
            self.f["persist"](result, self.home / "config.yaml")
            return result

        result = self._scoped(switch)
        if not getattr(result, "success", False):
            why = _short(str(getattr(result, "error_message", "") or "Hermes refused the model."), 900)
            raise ModelError("not_allowed", why)
        self._inventory = None
        config = self._config()
        current = self._current(config) or {"model": _id(getattr(result, "new_model", "")) or model,
                                             "provider": provider}
        return {"result": "set", **({"previous": previous} if previous else {}), "current": current,
                "revision": self._revision(config), "applies": "live"}
