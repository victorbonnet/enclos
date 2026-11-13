"""The app's routine controls, translated to Hermes's own cron store.

Only this sandbox process touches the runtime's store. Its lock surrounds
revision checks and mutations; scheduler registration happens after unlocking.
Replies are transient RPC results, never messages in the durable chat outbox.
"""

import contextlib
import copy
import hashlib
import inspect
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# The most live routines the app may have made for one agent: each runs
# unattended, so a lost phone cannot schedule work without bound.
MAX_APP_ROUTINES = 50

# How long the routine form's catalogues of skills, toolsets and models are
# kept before they are read again.
OPTIONS_SECONDS = 30


class RoutineError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _text(value, field, limit=512, optional=False):
    if optional and value is None:
        return None
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit or "\x00" in value:
        raise RoutineError("bad_message", f"Invalid {field}.")
    return value


def _choices(value, field):
    if not isinstance(value, list) or len(value) > 32:
        raise RoutineError("bad_message", f"Invalid {field}.")
    return [_text(item, field, 128) for item in value]


def _conversation(value):
    _text(value, "delivery", 128)
    if not value or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value):
        raise RoutineError("bad_message", "Invalid delivery conversation.")
    return value


# One item of a cron field: `*`, a number or a three-letter name, then an
# optional range end and step, as in `*/15`, `1-5` or `MON-FRI`.
_CRON_ITEM = r"(?:\*|\d{1,2}|[A-Za-z]{3})(?:-(?:\d{1,2}|[A-Za-z]{3}))?(?:/\d{1,2})?"
_CRON_FIELD = re.compile(rf"{_CRON_ITEM}(?:,{_CRON_ITEM})*")


def _is_cron(expression):
    """Five fields of cron's characters, names only for the month and the
    day of the week: "every monday at 9 am" is five words, not a cron
    expression, and Hermes would save it as another kind of schedule."""
    fields = expression.split()
    return len(fields) == 5 and all(
        _CRON_FIELD.fullmatch(field) and (index >= 3 or not re.search(r"[A-Za-z]", field))
        for index, field in enumerate(fields))


def _listable_id(value):
    """A native job id the app's list can carry: the bridge refuses a longer
    one, or one that does not show as itself."""
    return isinstance(value, (str, int)) and not isinstance(value, bool) and 0 < len(
        str(value).encode("utf-8")) <= 128 and str(value).isprintable() and bool(str(value).strip())


def _decodable(schedule):
    """Whether the bridge can read `schedule`, an app-format schedule."""
    kind = schedule.get("kind")
    if kind == "cron":
        return isinstance(schedule.get("expression"), str)
    if kind == "interval":
        return type(schedule.get("minutes")) is int and schedule["minutes"] >= 0
    if kind == "once":
        return isinstance(schedule.get("at"), str)
    return False


def validate_definition(value):
    if not isinstance(value, dict):
        raise RoutineError("bad_message", "A routine definition is required.")
    fields = {"name", "prompt", "schedule", "delivery", "skills", "model", "provider", "toolsets",
              "script", "script_only", "working_directory"}
    definition = {key: item for key, item in value.items() if key in fields}
    definition["prompt"] = _text(value.get("prompt"), "prompt", 8192)
    for key in ("name", "delivery", "model", "provider", "script", "working_directory"):
        if key in definition:
            definition[key] = _text(definition[key], key, optional=True)
    if definition.get("delivery") is not None:
        _conversation(definition["delivery"])
    definition["skills"] = _choices(value.get("skills", []), "skills")
    if definition.get("toolsets") is not None:
        definition["toolsets"] = _choices(definition["toolsets"], "toolsets")
    definition["script_only"] = value.get("script_only", False)
    if not isinstance(definition["script_only"], bool):
        raise RoutineError("bad_message", "script_only must be a boolean.")
    schedule = value.get("schedule")
    if not isinstance(schedule, dict):
        raise RoutineError("bad_message", "A schedule is required.")
    kind = schedule.get("kind")
    if kind == "cron":
        expression = _text(schedule.get("expression"), "cron expression", 128)
        if not _is_cron(expression):
            raise RoutineError("bad_message", "Use a five-field cron expression.")
        definition["schedule"] = {"kind": kind, "expression": expression}
    elif kind == "interval":
        minutes = schedule.get("minutes")
        if type(minutes) is not int or not 1 <= minutes <= 525600:
            raise RoutineError("bad_message", "An interval must be a positive number of minutes.")
        definition["schedule"] = {"kind": kind, "minutes": minutes}
    elif kind == "once":
        at = _text(schedule.get("at"), "one-shot time", 128)
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", at):
                raise ValueError()
            parsed = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if parsed.tzinfo is None or "T" not in at:
                raise ValueError()
        except ValueError:
            raise RoutineError("bad_message", "A one-shot needs an RFC3339 timestamp with an offset.") from None
        definition["schedule"] = {"kind": kind, "at": at}
    else:
        raise RoutineError("bad_message", "Unknown schedule kind.")
    if definition["script_only"] and not definition.get("script"):
        raise RoutineError("bad_message", "Script only requires a script.")
    if not (definition["prompt"].strip() or definition["skills"] or definition.get("script")):
        raise RoutineError("bad_message", "Supply a prompt, skill or script.")
    return definition


def validate_request(message):
    allowed = message.get("allowed_deliveries")
    if not isinstance(allowed, list) or len(allowed) > 4096:
        raise RoutineError("bad_message", "Trusted delivery scope is required.")
    for conversation in allowed:
        _conversation(conversation)
    # Who asked, as the bridge authenticated them: kept on what they create.
    if not _text(message.get("person"), "person", 256) or not _text(message.get("device"), "device", 128):
        raise RoutineError("bad_message", "The requesting person and device are required.")
    action = message.get("action")
    if action not in {"list", "get", "create", "update", "delete", "set_enabled", "run"}:
        raise RoutineError("bad_message", "Unknown routine action.")
    if action == "list":
        _text(message.get("cursor"), "cursor", 128, optional=True)
    elif action != "create":
        if not _text(message.get("routine"), "routine", 128):
            raise RoutineError("bad_message", "A routine id is required.")
    if action in {"update", "delete", "set_enabled", "run"}:
        if not _text(message.get("revision"), "revision", 128):
            raise RoutineError("bad_message", "A revision is required.")
    if action in {"create", "update"}:
        validate_definition(message.get("definition"))
    if action == "set_enabled" and not isinstance(message.get("enabled"), bool):
        raise RoutineError("bad_message", "enabled must be a boolean.")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def _short(value, characters=160):
    return str(value or "")[:characters].encode("utf-8")[:512].decode("utf-8", errors="ignore")


def _same_schedule(left, right):
    if left.get("kind") != right.get("kind"):
        return False
    if left.get("kind") == "once":
        try:
            return datetime.fromisoformat(left["at"].replace("Z", "+00:00")) == datetime.fromisoformat(right["at"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            return False
    if left.get("kind") == "cron":
        return left["expression"].split() == right["expression"].split()
    return left == right


def _error_summary(value):
    lines = str(value or "").strip().splitlines()
    if not lines:
        return ""
    return _short(lines[-1] if lines[0].startswith("Traceback") else lines[0], 512)


class Manager:
    def __init__(self, socket, home=None):
        self.socket = socket
        self.home_channel = None
        self.jobs = None
        self.dispatch = None
        self.runtime = lambda: (None, None)
        self._allowed = ContextVar("routine_allowed_deliveries", default=frozenset())
        self._replay_lock = threading.RLock()
        self._replies = OrderedDict()
        # The skill, toolset and model catalogues, and when they were read.
        self._options_read = None
        # Why routines are off, said once in the gateway's log: a Hermes
        # release that renames what this uses turns the capability off.
        self.unavailable = None
        try:
            from cron import jobs
            import hermes_constants
            from cron.scheduler_provider import CronScheduler, resolve_cron_scheduler
            required = ("create_job", "get_job", "list_jobs", "update_job", "pause_job", "resume_job",
                        "remove_job", "use_cron_store", "_jobs_lock")
            missing = [key for key in required if not callable(getattr(jobs, key, None))]
            if missing:
                return self._off(f"cron.jobs has no {', '.join(missing)}")
            # Hermes falls back to a process-only lock without this backend;
            # stale form revisions need the normal cross-process path.
            if not callable(getattr(getattr(jobs, "fcntl", None), "flock", None)):
                return self._off("cron.jobs has no fcntl file lock")
            if not all(callable(getattr(hermes_constants, key, None)) for key in
                       ("set_hermes_home_override", "reset_hermes_home_override")):
                return self._off("hermes_constants has no home override")
            parameters = inspect.signature(jobs.create_job).parameters
            if not {"prompt", "schedule", "name", "deliver", "origin"}.issubset(parameters):
                return self._off("cron.jobs.create_job takes other parameters")
            self.jobs = jobs
            self.constants = hermes_constants
            self.provider = resolve_cron_scheduler
            self.home = Path(home or hermes_constants.get_hermes_home()).resolve()
            self.parameters = parameters
            self.run_supported = all(callable(getattr(CronScheduler, key, None)) for key in ("claim_fire", "fire_claimed"))
        except Exception as error:
            self.jobs = None
            self._off(f"{type(error).__name__}: {error}")

    def _off(self, reason):
        self.unavailable = reason
        logger.warning("App routines are off for this Hermes: %s", reason)

    @property
    def available(self):
        return self.jobs is not None

    @contextlib.contextmanager
    def _scope(self):
        token = self.constants.set_hermes_home_override(str(self.home))
        try:
            with self.jobs.use_cron_store(self.home):
                yield
        finally:
            self.constants.reset_hermes_home_override(token)

    def _delivery(self, job):
        target = job.get("deliver") or "local"
        if target == "local":
            return None, "Nowhere", True
        if target == "enclos" and self.home_channel:
            return self.home_channel, "Home", self.home_channel in self._allowed.get()
        if isinstance(target, str) and target.startswith("enclos:") and "," not in target:
            conversation = target[len("enclos:"):]
            try:
                _conversation(conversation)
                return conversation, "Home" if conversation == self.home_channel else conversation, conversation in self._allowed.get()
            except RoutineError:
                pass
        origin = job.get("origin") or {}
        if target == "origin" and isinstance(origin, dict) and origin.get("platform") == "enclos":
            conversation = origin.get("chat_id")
            if isinstance(conversation, str) and conversation in self._allowed.get() and not origin.get("thread_id"):
                return conversation, "Home" if conversation == self.home_channel else conversation, conversation in self._allowed.get()
        return None, str(target)[:160], False

    def _definition(self, job):
        schedule = job.get("schedule")
        if not isinstance(schedule, dict):
            schedule = {}
        kind = schedule.get("kind")
        if kind == "cron":
            schedule = {"kind": kind, "expression": schedule.get("expr")}
        elif kind == "interval":
            schedule = {"kind": kind, "minutes": schedule.get("minutes")}
        elif kind == "once":
            schedule = {"kind": kind, "at": schedule.get("run_at")}
        definition = {"name": job.get("name"), "prompt": job.get("prompt") or "", "schedule": schedule,
                      "skills": job.get("skills") or ([job["skill"]] if job.get("skill") else []),
                      "model": job.get("model"), "provider": job.get("provider"),
                      "toolsets": job.get("enabled_toolsets"), "script": job.get("script"),
                      "script_only": bool(job.get("no_agent")), "working_directory": job.get("workdir")}
        delivery, _, _ = self._delivery(job)
        if delivery:
            definition["delivery"] = delivery
        return definition

    def _revision(self, job):
        fields = ("name", "prompt", "skills", "skill", "schedule", "deliver", "origin", "enabled",
                  "model", "provider", "base_url", "script", "no_agent", "enabled_toolsets", "workdir",
                  "monitor_script", "monitor_url", "context_from", "reasoning_effort", "failure_deliver",
                  "interpreter", "attach_to_session")
        return _digest({**{key: job.get(key) for key in fields},
                        "repeat_times": (job.get("repeat") or {}).get("times")})

    def _view(self, job, full=False):
        definition = self._definition(job)
        _, label, editable = self._delivery(job)
        if any(job.get(key) for key in ("monitor_script", "monitor_url", "context_from", "base_url", "failure_deliver", "attach_to_session")):
            editable = False
        try:
            validate_definition(definition)
        except RoutineError:
            editable = False
            if full:
                raise RoutineError("bad_message", "This native routine cannot fit the app's routine format.") from None
        _text(str(job["id"]), "native routine id", 128)
        result = {"id": str(job["id"]), "revision": self._revision(job),
                  "name": _short(job.get("name")), "schedule": definition["schedule"],
                  "enabled": bool(job.get("enabled", True)), "prompt_preview": _short(definition["prompt"]),
                  "delivery_label": _short(label), "editable": editable}
        for key in ("next_run_at", "last_run_at", "last_status", "state", "paused_reason", "last_error"):
            if isinstance(job.get(key), str):
                result[key] = _short(job[key], 512)
        if not result.get("last_error"):
            latest = job.get("latest_execution") or {}
            if isinstance(latest, dict) and isinstance(latest.get("error"), str):
                result["last_error"] = _short(latest["error"], 512)
        if result.get("last_error"):
            result["last_error"] = _error_summary(job.get("last_error") or result["last_error"])
        if full:
            if definition.get("delivery") not in self._allowed.get():
                definition.pop("delivery", None)
            result["definition"] = definition
        return result

    def _listed(self, job):
        """The job's summary for a list page, or None for a job the app's
        format cannot carry (no schedule, another kind, a null field, a long
        id), which a hand-edited jobs.json or a later Hermes can hold: one
        such job must not stop the others from being listed."""
        if not (_listable_id(job.get("id")) and _decodable(self._definition(job)["schedule"])):
            logger.warning("Routine %.80r is left out of the app's list: the app cannot show it.", job.get("id"))
            return None
        return self._view(job)

    def _native_fields(self, definition, saved_script=None):
        if definition.get("delivery") and definition["delivery"] not in self._allowed.get():
            raise RoutineError("unsupported", "This conversation is outside the routine's allowed delivery scope.")
        schedule = definition["schedule"]
        text = (schedule["expression"] if schedule["kind"] == "cron" else
                f"every {schedule['minutes']}m" if schedule["kind"] == "interval" else schedule["at"])
        fields = {"name": definition.get("name"), "prompt": definition["prompt"], "schedule": text,
                  "deliver": f"enclos:{definition['delivery']}" if definition.get("delivery") else "local"}
        optional = {"skills": definition["skills"], "model": definition.get("model"),
                    "provider": definition.get("provider"), "enabled_toolsets": definition.get("toolsets"),
                    "script": definition.get("script"), "no_agent": definition["script_only"],
                    "workdir": definition.get("working_directory")}
        for key, value in optional.items():
            if key not in self.parameters:
                if value not in (None, False, []):
                    raise RoutineError("unsupported", f"This Hermes version does not support {key}.")
                continue
            fields[key] = value
        # A script the routine already had stays as Hermes saved it, even
        # one an older Hermes stored as an absolute path.
        if fields.get("script") and fields["script"] != saved_script:
            raw = Path(fields["script"])
            root = (self.home / "scripts").resolve()
            if raw.is_absolute() or fields["script"].startswith("~"):
                raise RoutineError("bad_message", "Script must be relative to this agent's scripts directory.")
            path = (root / raw).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise RoutineError("bad_message", "Script must be an existing file inside this agent's scripts directory.")
            fields["script"] = str(path.relative_to(root))
        if fields.get("workdir") and not Path(fields["workdir"]).is_absolute():
            raise RoutineError("bad_message", "Working directory must be an absolute path.")
        return fields

    def _receipt_path(self, request):
        return Path(self.socket + ".routine-creates") / (_digest(request) + ".json")

    def _receipt(self, request):
        path = self._receipt_path(request)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("job"), str):
                raise ValueError()
            return value
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise RoutineError("conflict", "The previous create outcome cannot be recovered; refresh the routine list.") from None

    def _save_receipt(self, request, fingerprint, job):
        path = self._receipt_path(request)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_suffix(".new")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"schema_version": 1, "fingerprint": fingerprint, "job": job["id"]}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _create(self, message):
        definition = validate_definition(message["definition"])
        fingerprint = _digest(definition)
        with self.jobs._jobs_lock():
            receipt = self._receipt(message["id"])
            if receipt:
                if receipt.get("fingerprint") != fingerprint:
                    raise RoutineError("conflict", "This create request was already used with another definition.")
                job = self.jobs.get_job(receipt["job"])
                if job is None:
                    raise RoutineError("not_found", "The routine created by this request was deleted.")
            else:
                job = next((item for item in self.jobs.list_jobs(include_disabled=True)
                            if isinstance(item.get("origin"), dict)
                            and item["origin"].get("_enclos_request") == message["id"]), None)
                if job and job["origin"].get("_enclos_definition") != fingerprint:
                    raise RoutineError("conflict", "This create request was already used with another definition.")
                if job is None:
                    made = sum(1 for item in self.jobs.list_jobs(include_disabled=True)
                               if isinstance(item.get("origin"), dict) and item["origin"].get("_enclos_request"))
                    if made >= MAX_APP_ROUTINES:
                        raise RoutineError("not_allowed", f"This agent already has {MAX_APP_ROUTINES} routines made "
                                                          "from the app. Delete one before creating another.")
                    fields = self._native_fields(definition)
                    # Who made it, from where: the routine runs long after,
                    # and outlives the device that made it.
                    fields["origin"] = {"platform": "enclos", "chat_id": self.home_channel or "",
                                        "_enclos_request": message["id"], "_enclos_definition": fingerprint,
                                        "_enclos_person": message["person"], "_enclos_device": message["device"]}
                    job = self.jobs.create_job(**fields)
                self._save_receipt(message["id"], fingerprint, job)
        # Registration may call back into storage or a remote provider. Never hold the store lock.
        if job.get("enabled", True):
            try:
                self.provider().register_job(job)
            except Exception:
                raise RoutineError("unknown", f"Routine {job['id']} was saved but scheduler registration failed. Refresh and enable it again; do not create another routine.") from None
        return {"result": "routine", "routine": self._view(job, full=True)}

    def _notify(self):
        try:
            self.provider().on_jobs_changed()
        except Exception:
            # Same best-effort semantics as native dashboard edits; the job remains saved.
            pass

    def _options(self):
        """The routine form's choices, read again at most every
        `OPTIONS_SECONDS`: building the catalogues for every list page
        reads the skills, toolsets and model inventory each time."""
        now = time.monotonic()
        if self._options_read and now - self._options_read[0] < OPTIONS_SECONDS:
            return copy.deepcopy(self._options_read[1])
        options = self._read_options()
        self._options_read = (now, options)
        return copy.deepcopy(options)

    def _read_options(self):
        timezone = "Server local time"
        try:
            from hermes_time import get_timezone_name, now
            timezone = get_timezone_name() or str(now().tzinfo)
        except Exception:
            pass
        features = [app for native, app in (("skills", "skills"), ("model", "model"),
                    ("provider", "provider"), ("enabled_toolsets", "toolsets"), ("script", "script"),
                    ("workdir", "working_directory")) if native in self.parameters]
        if self.run_supported and callable(self.dispatch):
            features.append("run")
        if "no_agent" in self.parameters and "script" in self.parameters:
            features.append("script_only")
        options = {"timezone": timezone, "features": features, "skills": [], "models": [], "toolsets": []}
        try:
            from tools.skills_tool import find_all_skills
            options["skills"] = [{"id": s["name"], "label": s["name"]} for s in find_all_skills(skip_disabled=True)][:100]
        except Exception:
            pass
        try:
            import toolsets
            options["toolsets"] = [{"id": name, "label": name} for name in sorted(toolsets.get_all_toolsets())][:100]
        except Exception:
            pass
        try:
            from hermes_cli.inventory import build_models_payload, load_picker_context
            parameters = inspect.signature(build_models_payload).parameters
            flags = {"include_unconfigured": False, "non_blocking_catalogs": True,
                     "probe_custom_providers": False, "probe_current_custom_provider": False, "max_models": 100}
            payload = build_models_payload(load_picker_context(), **{key: value for key, value in flags.items() if key in parameters})
            # Inventory shapes vary across Hermes releases. Only advertised model IDs are used.
            models = []
            for provider in payload.get("providers", []):
                if isinstance(provider, dict):
                    for model in provider.get("models", []):
                        identifier = model.get("id") if isinstance(model, dict) else model
                        if isinstance(identifier, str):
                            slug = provider.get("slug")
                            label = f"{slug}: {identifier}" if slug else identifier
                            row = {"id": identifier, "label": label.encode("utf-8")[:128].decode("utf-8", errors="ignore")}
                            if isinstance(slug, str) and slug:
                                row["provider"] = slug
                            models.append(row)
            options["models"] = models[:100]
        except Exception:
            pass
        for key in ("skills", "models", "toolsets"):
            options[key] = [item for item in options[key] if all(isinstance(v, str) and 0 < len(v.encode("utf-8")) <= 128 for v in item.values())][:20]
        return options

    def handle(self, message):
        try:
            return self._control(message)
        except RoutineError:
            raise
        except Exception:
            raise RoutineError("unknown", "The operation's outcome is unknown. Refresh before trying again.") from None

    def _control(self, message):
        validate_request(message)
        if not self.available:
            raise RoutineError("unsupported", "This Hermes version does not support app routines.")
        if message["action"] == "create":
            with self._replay_lock:
                if message["id"] in self._replies:
                    raise RoutineError("conflict", "This request id was already used for another operation.")
                return self._bounded_handle(message)
        if message["action"] not in {"update", "delete", "set_enabled", "run"}:
            return self._bounded_handle(message)
        fingerprint = _digest({key: message[key] for key in
                              ("action", "routine", "revision", "definition", "enabled") if key in message})
        # Claim the request before entering native code. Connection resets do not
        # repeat a recent run or mutation; the bridge also has its own live cache.
        with self._replay_lock:
            with self._scope():
                if self._receipt(message["id"]) is not None:
                    raise RoutineError("conflict", "This request id was already used to create a routine.")
            previous = self._replies.get(message["id"])
            if previous:
                if previous["fingerprint"] != fingerprint:
                    raise RoutineError("conflict", "This request id was already used for another operation.")
                self._replay_scope(message, previous["targets"])
                self._replies.move_to_end(message["id"])
                if "error" in previous:
                    raise RoutineError(*previous["error"])
                return copy.deepcopy(previous["result"])
            targets = self._replay_scope(message)
            entry = {"fingerprint": fingerprint, "targets": targets}
            try:
                result = self._bounded_handle(message)
                entry["result"] = copy.deepcopy(result)
                return result
            except RoutineError as error:
                entry["error"] = (error.code, str(error))
                raise
            except Exception:
                error = RoutineError("unknown", "The operation's outcome is unknown. Refresh before trying again.")
                entry["error"] = (error.code, str(error))
                raise error from None
            finally:
                self._replies[message["id"]] = entry
                while len(self._replies) > 128:
                    self._replies.popitem(last=False)

    def _replay_scope(self, message, previous_targets=()):
        if not self.available:
            raise RoutineError("unsupported", "This Hermes version does not support app routines.")
        allowed = frozenset(message["allowed_deliveries"])
        targets = set(previous_targets)
        delivery = (message.get("definition") or {}).get("delivery")
        if delivery:
            targets.add(delivery)
        token = self._allowed.set(allowed)
        try:
            with self._scope():
                job = self.jobs.get_job(message["routine"])
                if job:
                    native_delivery, _, supported = self._delivery(job)
                    if not supported or not self._view(job)["editable"]:
                        raise RoutineError("unsupported", "The routine's current destination is outside this app's scope.")
                    if native_delivery:
                        targets.add(native_delivery)
            if not targets.issubset(allowed):
                raise RoutineError("unsupported", "The routine's destination is outside this app's current scope.")
            return targets
        finally:
            self._allowed.reset(token)

    def _bounded_handle(self, message):
        result = self._handle(message)
        # Leave room for the bridge's delivery choices in a device control frame.
        if result["result"] == "list":
            while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 44000 and result["routines"]:
                result["routines"].pop()
                if result["routines"]:
                    result["next_cursor"] = result["routines"][-1]["id"]
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 44000:
            raise RoutineError("bad_message", "The native routine is too large to display in the app.")
        return result

    def execute(self, provider, claimed):
        """The accepted native snapshot, dispatched off the gateway's event loop."""
        with self._scope():
            adapters, loop = self.runtime()
            try:
                provider.fire_claimed(claimed, adapters=adapters, loop=loop)
            finally:
                self._notify()

    def _handle(self, message):
        if not self.available:
            raise RoutineError("unsupported", "This Hermes version does not support app routines.")
        validate_request(message)
        token = self._allowed.set(frozenset(message["allowed_deliveries"]))
        try:
            with self._scope():
                action = message["action"]
                if action == "list":
                    cursor = message.get("cursor") or ""
                    jobs = [job for job in self.jobs.list_jobs(include_disabled=True)
                            if isinstance(job, dict) and job.get("id") is not None]
                    jobs = sorted((job for job in jobs if str(job["id"]) > cursor), key=lambda job: str(job["id"]))
                    result = {"result": "list", "routines": [], "options": self._options()}
                    for job in jobs:
                        view = self._listed(job)
                        if view is None:
                            continue
                        if len(result["routines"]) == 25:
                            result["next_cursor"] = result["routines"][-1]["id"]
                            break
                        result["routines"].append(view)
                    return result
                if action == "create":
                    return self._create(message)
                provider = self.provider() if action == "run" else None
                claimed = None
                with self.jobs._jobs_lock():
                    job = self.jobs.get_job(message["routine"])
                    if job is None:
                        raise RoutineError("not_found", "The routine no longer exists.")
                    if action == "get":
                        return {"result": "routine", "routine": self._view(job, full=True)}
                    if not self._view(job)["editable"]:
                        raise RoutineError("unsupported", "Manage this routine in Hermes; its delivery is outside the app.")
                    if self._revision(job) != message["revision"]:
                        raise RoutineError("conflict", "The routine changed. Refresh before trying again.")
                    if action == "update":
                        definition = validate_definition(message["definition"])
                        fields = self._native_fields(definition, saved_script=job.get("script"))
                        # Sending an unchanged schedule re-anchors Hermes intervals and can
                        # reject an old one-shot while merely changing its prompt.
                        if _same_schedule(definition["schedule"], self._definition(job)["schedule"]):
                            fields.pop("schedule", None)
                        fields = {key: value for key, value in fields.items() if key == "schedule" or job.get(key) != value}
                        if fields:
                            job = self.jobs.update_job(job["id"], fields)
                    elif action == "set_enabled":
                        job = (self.jobs.resume_job if message["enabled"] else self.jobs.pause_job)(job["id"])
                    elif action == "delete":
                        self.jobs.remove_job(job["id"])
                    elif action == "run":
                        if not self.run_supported or not callable(self.dispatch):
                            raise RoutineError("unsupported", "This Hermes version cannot run routines from the app.")
                        if not job.get("enabled", True) or job.get("state") == "paused" or job.get("paused_at"):
                            raise RoutineError("conflict", "Resume this routine before running it.")
                        claimed = provider.claim_fire(job["id"], manual=True)
                        if not isinstance(claimed, dict):
                            raise RoutineError("conflict", "The routine is already running or cannot be claimed.")
                if claimed is not None:
                    # No store lock crosses the execution hand-off. The native claim is
                    # durable before the RPC acknowledges acceptance.
                    self.dispatch(provider, claimed)
                self._notify()
                if action in {"delete", "run"}:
                    return {"result": "deleted" if action == "delete" else "run", "routine": job["id"]}
                return {"result": "routine", "routine": self._view(job, full=True)}
        except RoutineError:
            raise
        except (ValueError, TypeError) as error:
            raise RoutineError("bad_message", str(error)[:512]) from None
        except Exception:
            raise RoutineError("unknown", "The runtime could not confirm this operation. Refresh before trying again.") from None
        finally:
            self._allowed.reset(token)
