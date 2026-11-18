"""The agent's model, read and changed from the app (`model.request`).

Hermes keeps it: its own inventory lists the model providers and their
models, and its own `/model --global` path (`switch_model`, then
`persist_model_selection`) checks a choice and saves it in the agent's
`config.yaml`. Read in Hermes's source, its gateway loads that file for each
turn, so a saved choice is expected to apply on the agent's next turn
without a restart (to verify on a host, enclos design §14); enclos's
settings watch then restarts nothing when only the file's `model` block
changed, which `restart_free` follows here so that `applies` says the same.
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
# The most bytes of a `model.response` line (enclos_protocol::model::MAX_REPLY_BYTES).
MAX_REPLY_BYTES = 44 * 1024
# How long one reading of the inventory serves `options` and `models`.
INVENTORY_SECONDS = 60
UNKNOWN = "The outcome is unknown: open the agent's model again before retrying."


class ModelError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _short(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _id(value):
    """A model provider's or model's id the protocol can carry, else None."""
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


def _size(result):
    return len(json.dumps(result, ensure_ascii=False).encode("utf-8")) + 200


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


def without_top_level(text, key):
    """`text` without its top-level `key` block, or None for YAML this reader
    does not follow. The same rules as enclos's Hermes adapter
    (`src/runtime/hermes/facts.rs`, `without_top_level`), which decides
    whether a change of `config.yaml` restarts the gateway."""
    def indent(line):
        return len(line) - len(line.lstrip(" "))

    def anchor_or_alias(line):
        for i, c in enumerate(line):
            if c in "&*" and (i == 0 or line[i - 1] in " [{,") and i + 1 < len(line) \
                    and (line[i + 1].isalnum() or line[i + 1] in "_-"):
                return True
        return False

    def unsure(line):
        leading = line[:len(line) - len(line.lstrip())]
        return ("\t" in leading or line.startswith(("---", "...", "%", "{", "["))
                or line.lstrip().startswith("<<") or anchor_or_alias(line))

    def opens_block_scalar(line):
        content = line.split(" #")[0].rstrip()
        last = content.split(" ")[-1]
        before = content[:len(content) - len(last)].rstrip()
        return (last[:1] in ("|", ">") and all(c in "+-" or c.isdigit() for c in last[1:])
                and (before.endswith(":") or before.endswith("-")))

    def top_key(line):
        if line and not line[0].isspace() and line[0] not in "#-":
            return line.split(":")[0].strip()
        return None

    kept, inside, seen, scalar = [], False, False, None
    for line in text.splitlines():
        if scalar is not None:
            if not line.strip() or indent(line) > scalar:
                if not inside:
                    kept.append(line)
                continue
            scalar = None
        if unsure(line):
            return None
        name = top_key(line)
        if name in (key, f'"{key}"', f"'{key}'"):
            if seen:
                return None
            seen = inside = True
        elif name is not None:
            inside = False
            kept.append(line)
        elif inside and line.startswith("-"):
            return None
        elif not inside:
            kept.append(line)
        if opens_block_scalar(line):
            scalar = indent(line)
    return "\n".join(kept)


def restart_free(text):
    """Whether a change of this `config.yaml`'s `model` block alone leaves
    enclos's settings watch without a restart."""
    return without_top_level(text, "model") is not None


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
            # The home Hermes gave this adapter must be the agent's own:
            # another's would have the app change that agent's model.
            profile = self.f.get("profile")
            if profile is not None and profile(self.home) != agent:
                raise LookupError(f"this adapter's Hermes home {self.home} is not the agent {agent}'s")
        except Exception as error:
            self.f = None
            self.unavailable = f"{type(error).__name__}: {error}"
            # A Hermes that is installed but lacks what this uses needs the
            # plugin adapted; one not installed (tests) is expected.
            log = logger.warning if isinstance(error, ModuleNotFoundError) else logger.error
            log("Choosing the model from the app is off for this Hermes: %s", self.unavailable)

    @staticmethod
    def _hermes():
        import hermes_constants
        from hermes_cli import config, inventory, model_switch
        needed = {
            "config": getattr(config, "load_config", None),
            "home": getattr(hermes_constants, "get_hermes_home", None),
            "scope": getattr(hermes_constants, "set_hermes_home_override", None),
            "unscope": getattr(hermes_constants, "reset_hermes_home_override", None),
            "profile": getattr(hermes_constants, "profile_name_for_home", None),
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
        # The `model` block as Hermes loads it (its defaults, the file,
        # managed settings, variables expanded).
        block = json.dumps(config.get("model"), sort_keys=True, default=str)
        return hashlib.sha256(block.encode("utf-8")).hexdigest()[:32]

    def _applies(self):
        try:
            text = (self.home / "config.yaml").read_text(encoding="utf-8")
        except FileNotFoundError:
            return "live"
        except OSError:
            return "restart"
        return "live" if restart_free(text) else "restart"

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
            raise TypeError("Hermes's model inventory is not a mapping")
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
        # Hermes's inventory adds model providers with no login or secret as
        # setup skeletons (`source: canonical`), and keeps the current one
        # without one marked `authenticated: false`.
        return row.get("authenticated") is not False and row.get("source") != "canonical"

    def _setup(self, row):
        key = _id(row.get("key_env"))
        how = f"run `hermes -p {self.agent} model` in an `enclos connect` session on the host"
        if key:
            return f"Set it up on the host: grant {key} to the agent in the sandbox's policy, or {how}."
        return f"Set it up on the host: {how}."

    @staticmethod
    def _models(row):
        models = []
        for item in row.get("models") or []:
            identifier = _id(item.get("id") if isinstance(item, dict) else item)
            if identifier is None or any(m["id"] == identifier for m in models):
                continue
            name = (item.get("name") or item.get("label")) if isinstance(item, dict) else None
            models.append({"id": identifier, "label": _label(name, identifier)})
        total = row.get("total_models")
        limited = len(models) > MAX_MODELS or (isinstance(total, int) and total > len(models))
        return models[:MAX_MODELS], limited

    # The requests

    def handle(self, message):
        validate_request(message)
        with self._lock:
            return self._handle(message)

    def _read(self, what, call):
        """A read: a failure changed nothing, and says why."""
        try:
            return call()
        except ModelError:
            raise
        except Exception as error:
            logger.error("Reading %s for the app failed", what, exc_info=True)
            raise ModelError("agent_unavailable",
                             f"Hermes could not read {what} ({type(error).__name__}). Nothing was changed.") from None

    def _handle(self, message):
        action = message["action"]
        if action == "options":
            return self._read("the agent's model settings", self._options)
        if action == "models":
            return self._read("its model inventory", lambda: self._list(message["provider"]))
        return self._set(message["provider"], message["model"], message["revision"])

    def _options(self):
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
        result = {"result": "options", **({"current": current} if current else {}),
                  "revision": self._revision(config), "applies": self._applies(),
                  "providers": providers, "custom_models": True}
        if _size(result) > MAX_REPLY_BYTES:
            raise ModelError("unsupported", "Hermes lists too many model providers to show on the phone.")
        return result

    def _list(self, provider):
        row = self._rows(self._payload()).get(provider)
        if row is None:
            raise ModelError("not_found", "Hermes does not list that model provider.")
        models, limited = self._models(row)
        result = {"result": "models", "provider": provider, "models": models, "limited": limited}
        while _size(result) > MAX_REPLY_BYTES and result["models"]:
            result["models"] = result["models"][:len(result["models"]) * 9 // 10]
            result["limited"] = True
        return result

    def _set(self, provider, model, revision):
        def before():
            config = self._config()
            if self._revision(config) != revision:
                raise ModelError("conflict", "The agent's model changed since it was read. Open it again.")
            row = self._rows(self._payload()).get(provider)
            if row is None:
                raise ModelError("not_found", "Hermes does not list that model provider.")
            if not self._usable(row):
                raise ModelError("not_allowed", f"The agent cannot use {provider} yet. {self._setup(row)}")
        self._read("the agent's model settings", before)
        saving = {"started": False}
        previous = {}

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
            # Checked again just before saving: Hermes's save merges a
            # change made meanwhile (on the host, by the agent) rather than
            # refusing it, and checking the model may have taken a while.
            config = self.f["config"]()
            if self._revision(config if isinstance(config, dict) else {}) != revision:
                raise ModelError("conflict", "The agent's model changed while it was being saved. Open it again.")
            previous["value"] = self._current(config)
            saving["started"] = True
            self.f["persist"](result, self.home / "config.yaml")
            return result

        try:
            result = self._scoped(switch)
        except ModelError:
            raise
        except Exception as error:
            logger.error("Saving the model %s (%s) for the app failed", model, provider, exc_info=True)
            if saving["started"]:
                raise ModelError("unknown", UNKNOWN) from None
            raise ModelError("agent_unavailable",
                             f"Hermes could not check the model ({type(error).__name__}). Nothing was changed.") from None
        if not getattr(result, "success", False):
            why = _short(str(getattr(result, "error_message", "") or "Hermes refused the model."), 900)
            logger.info("Hermes refused the model %s (%s) for the app: %s", model, provider, why)
            raise ModelError("not_allowed", why)
        self._inventory = None
        try:
            config = self._config()
        except Exception:
            logger.error("Reading the agent's model back after saving failed", exc_info=True)
            raise ModelError("unknown", "Saved, but the agent's model could not be read back. Open it again.") from None
        current = self._current(config)
        if current is None or current.get("provider") != provider:
            raise ModelError("unknown", "Saved, but the agent's model could not be read back. Open it again.")
        return {"result": "set", **({"previous": previous["value"]} if previous.get("value") else {}),
                "current": current, "revision": self._revision(config), "applies": self._applies()}
