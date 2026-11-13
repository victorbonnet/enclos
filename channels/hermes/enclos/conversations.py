"""Delete through Hermes's live session owner, as its mobile REST endpoint does.

Never delete SQLite rows behind a running gateway. Older releases use the guarded native deletion API their mobile REST endpoint
uses, including routing retirement; a release lacking both APIs is Unsupported.
"""
import asyncio
import logging
import importlib.util
import inspect
import sys
from pathlib import Path

from . import protocol

logger = logging.getLogger(__name__)


class DeleteError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def capture_home():
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home()).resolve()
    except ImportError:
        return None


def authority(adapter):
    from gateway.session_authorities import authority_for_home
    # The adapter captured its agent's home at connection, rather than relying
    # on the launch profile's globals from a socket callback.
    if adapter._conversation_home is None:
        return None
    return authority_for_home(adapter.gateway_runner, adapter._conversation_home)


def owner_api_present():
    if "gateway.session_mutations" in sys.modules:
        return True
    try:
        return importlib.util.find_spec("gateway.session_mutations") is not None
    except (ImportError, ValueError):
        return False


def available(adapter):
    try:
        if owner_api_present():
            from gateway.session_mutations import mutate_session  # noqa: F401
            return authority(adapter) is not None and getattr(adapter, "_session_store", None) is not None
        # Pre-owner Hermes uses this same guarded SessionDB API in its mobile
        # REST endpoint. Require routing retirement too, so it cannot resurrect.
        from hermes_state import SessionDB
        runner = getattr(adapter, "gateway_runner", None)
        store = getattr(adapter, "_session_store", None)
        return (adapter._conversation_home is not None
                and "exclude_active_write_guards" in inspect.signature(SessionDB.delete_session).parameters
                and all(callable(getattr(store, name, None)) for name in ("peek_session_id", "remove_by_session_id", "_db_for_key"))
                and all(callable(getattr(runner, name, None)) for name in ("_is_session_running", "_evict_cached_agent")))
    except (ImportError, AttributeError, ValueError):
        return False


def session_key(adapter, chat_id):
    from gateway.session import build_session_key
    source = adapter.build_source(chat_id=chat_id, chat_name=chat_id, chat_type="dm")
    adapter._canonicalize(source)
    return build_session_key(source, profile=adapter._session_key_profile(source))


def session_id(adapter, chat_id):
    store = getattr(adapter, "_session_store", None)
    if store is None:
        raise DeleteError("unsupported", "This Hermes gateway cannot delete conversations. Update Hermes and its app channel.")
    return store.peek_session_id(session_key(adapter, chat_id))


async def legacy_delete(adapter, chat_id):
    """The older mobile endpoint's guarded delete, on this gateway's owning DB."""
    key = session_key(adapter, chat_id)
    store, runner = adapter._session_store, adapter.gateway_runner
    db = store._db_for_key(key)
    home = adapter._conversation_home
    if db is None or Path(db.db_path).resolve().parent != home:
        raise DeleteError("unsupported", "The owning Hermes database is unavailable. Retry after the agent reconnects.")
    if runner._is_session_running(key):
        # Use the real gateway command, which also clears pending busy messages.
        await adapter._on_message({"id": protocol.new_id(), "conversation": chat_id,
                                   "person": "enclos-app", "text": "/stop"})
        for _ in range(40):
            if not runner._is_session_running(key):
                break
            await asyncio.sleep(0.25)
    if runner._is_session_running(key):
        raise DeleteError("conflict", "Hermes is still stopping this conversation. Retry Delete shortly.")
    sid = store.peek_session_id(key)
    if sid is None:
        return
    # Ancestors first and current tip last: a refused guard leaves the route's
    # tip intact so a retry can discover and finish its remaining lineage.
    lineage = await asyncio.to_thread(db.get_compression_lineage, sid)
    for target in lineage or [sid]:
        await asyncio.to_thread(db.delete_session, target, sessions_dir=home / "sessions", exclude_active_write_guards=True)
        await asyncio.to_thread(store.remove_by_session_id, target)
    runner._evict_cached_agent(key)


async def delete(adapter, chat_id, request_id):
    if not owner_api_present():
        await legacy_delete(adapter, chat_id)
        return
    from gateway.session_contract import Principal, SessionRef
    from gateway.session_mutations import mutate_session
    from gateway.session_route_recovery import messaging_owner_ref
    owner = authority(adapter)
    if owner is None:
        raise DeleteError("unsupported", "This Hermes gateway has no session owner. Update Hermes and its app channel.")
    sid = session_id(adapter, chat_id)
    if sid is None:
        return  # Empty chat, or the native deletion committed before its Ack was lost.
    actor = Principal("enclos-app", owner.profile_id,
                      frozenset({"session:read", "session:control"}), "enclos-plugin")
    ref = messaging_owner_ref(owner, SessionRef(owner.profile_id, sid))
    row = await asyncio.to_thread(owner.db.get_session, ref.session_id)
    if row is None:
        return
    # Native Stop and queued cancellation release the same admissions the delete
    # guard checks. A still-running or unknown outcome remains a refusal, never
    # a direct database delete; the phone may retry once Hermes has settled it.
    handle = await owner.resolve(actor, ref)
    for queued in owner._pending_rows(ref):
        if queued["status"] == "queued":
            await owner.cancel_queued(actor, ref, queued["admission_id"])
    if handle.execution_state == "running":
        await owner.interrupt(actor, ref, handle.execution_generation)
        for _ in range(40):
            await asyncio.sleep(0.25)
            handle = await owner.resolve(actor, ref)
            if handle.execution_state != "running":
                break
    row = await asyncio.to_thread(owner.db.get_session, ref.session_id)
    if row is None:
        return
    result = await mutate_session(owner, actor, ref, {
        "session_id": ref.session_id, "request_id": request_id,
        "expected_revision": row["runtime_revision"],
        "expected_generation": row["runtime_generation"], "operation": "delete", "payload": {},
    })
    # Match the REST endpoint: the authority retires rows and routes; its
    # native cleanup removes transcript snapshots and request dumps too.
    from hermes_state import SessionDB
    for deleted in result.get("deleted_ids") or ():
        await asyncio.to_thread(SessionDB._remove_session_files, Path(owner.profile_id) / "sessions", str(deleted))


async def handle(adapter, message):
    chat_id = message["conversation"]
    if chat_id == adapter._routines.home_channel or chat_id.startswith("home."):
        await adapter._write(protocol.error("not_allowed", "Home cannot be deleted.", message["id"]))
        return
    if not available(adapter):
        await adapter._write(protocol.error("unsupported", "Update Hermes and its app channel to delete conversations.", message["id"]))
        return
    try:
        await delete(adapter, chat_id, message["id"])
    except Exception as error:
        reason = getattr(error, "reason", None)
        if type(error).__name__ == "SessionActiveWriteGuardError":
            reason = "session_busy"
        code = getattr(error, "code", None) or ("conflict" if reason else "internal")
        text = str(error) if isinstance(error, DeleteError) else (
            "Hermes has not finished stopping this conversation. Retry Delete shortly."
            if reason == "session_busy" else "Hermes could not confirm deletion. Retry Delete.")
        logger.warning("[%s] Conversation deletion failed (%s)", adapter.name, reason or type(error).__name__)
        await adapter._write(protocol.error(code, text, message["id"]))
        return
    pending = adapter._title_checks.pop(chat_id, None)
    if pending is not None:
        pending.cancel()
    adapter._titles.pop(chat_id, None)
    adapter._last_in.pop(chat_id, None)
    await adapter._write(protocol.ack(message["id"]))
