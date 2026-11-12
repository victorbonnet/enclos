"""Policy context is advisory knowledge; only enclos on the host can grant access.

Request messages use the existing durable outbox. No command, file contents or
full tool output is sent to the host or the phone.
"""
import asyncio
import json
import os
from pathlib import Path
from . import protocol


def save_context(socket: str, text: str) -> None:
    path = socket + ".policy-context"
    temp = path + ".new"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text[:48000])
    os.replace(temp, path)


def request(conversation: str, kind: str, target: str, action: str = "", private: bool = False) -> dict:
    if kind not in ("network", "write", "read") or not target or len(target) > 4096 or any(ord(c) < 32 for c in target):
        raise ValueError("Name one destination or absolute path, with kind network, write or read.")
    return protocol._message("approval.request", conversation=conversation,
        access={"kind": kind, "target": target, "private": private},
        action=(action or f"{kind.capitalize()} {target}")[:240])


def blocked_file(tool_name, args, result, error_message=""):
    """A concrete file tool refused one path. Shell commands cannot be parsed safely:
    their network refusals are recorded by the proxy, and the agent can request a
    filesystem scope explicitly with enclos_request_access.
    """
    kinds = {"write_file": "write", "patch": "write", "read_file": "read"}
    kind = kinds.get(tool_name)
    if not kind or not isinstance(args, dict):
        return None
    target = args.get("path") or args.get("file_path")
    if not isinstance(target, str) or not os.path.isabs(target):
        return None
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            return None
    if not isinstance(result, dict):
        return None
    error = str(result.get("error") or error_message or "").lower()
    if not any(s in error for s in ("permission denied", "operation not permitted", "read-only file system")):
        return None
    return kind, target


def routes(adapters, conversation):
    """The agents' connections a request for `conversation` goes through.

    One gateway serves every agent of the sandbox, and its process
    environment names only the first agent's socket. So a request goes
    through the agents the conversation reached (one, or a group's members),
    or, before any message came, through every connected agent: the bridge
    keeps it only for an agent of that conversation.
    """
    live = list(adapters)
    return [a for a in live if conversation in getattr(a, "_last_in", {})] or live


def session(platform):
    """The current turn's conversation, if it is an enclos one."""
    from gateway.session_context import get_session_env
    if get_session_env("HERMES_SESSION_PLATFORM") != platform:
        return None
    return get_session_env("HERMES_SESSION_CHAT_ID") or None


def register(ctx, adapters, socket_path, platform="enclos"):
    def context(**_):
        conversation = session(platform)
        through = routes(adapters, conversation) if conversation else []
        path = through[0]._path if through else socket_path()
        try:
            text = Path(path + ".policy-context").read_text()[:48000]
        except OSError:
            text = "Enclos policy context is not available yet. A request never grants access."
        return {"context": text + " If an action is blocked, call enclos_request_access with its exact destination or path, then wait for the person to approve in their inbox. Do not repeatedly retry or bypass the sandbox. The policy, not this description, enforces access."}

    async def enqueue(adapter, message):
        if not adapter._outbox.put(message):
            raise RuntimeError("The request outbox is full; the request was not saved.")
        await adapter._write(message)

    def ask(args, **_):
        kind, target, action, private = args.get("kind"), args.get("target"), args.get("action", ""), args.get("private", False)
        try:
            conversation = session(platform)
            through = routes(adapters, conversation) if conversation else []
            if not through:
                return json.dumps({"error": "No enclos conversation is active."})
            message = request(conversation, kind, target, action, private)
            for adapter in through:
                asyncio.run_coroutine_threadsafe(enqueue(adapter, message), adapter._loop).result(timeout=5)
            return json.dumps({"status": "requested", "message": "Waiting for approval in the person's inbox. Access has not been granted. Do not retry until the active policy context grants it."})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def after(tool_name="", args=None, result=None, error_message="", **_):
        scope = blocked_file(tool_name, args, result, error_message)
        if scope:
            # Observer hooks return promptly; no network or wait on their worker.
            conversation = session(platform)
            if conversation:
                message = request(conversation, *scope)
                for adapter in routes(adapters, conversation):
                    asyncio.run_coroutine_threadsafe(enqueue(adapter, message), adapter._loop)

    ctx.register_hook("pre_llm_call", context)
    ctx.register_hook("post_tool_call", after)
    ctx.register_tool(name="enclos_request_access", toolset="enclos", description="Ask the person to approve one sandbox policy scope in their mobile inbox; does not grant access or retry the action.", handler=ask,
        schema={"name": "enclos_request_access", "description": "Request access after a sandbox refusal. The person may approve or deny; wait for approval. Network: one host:port, write/read: one absolute path. Never send secrets or file contents.",
                "parameters": {"type": "object", "properties": {
                    "kind": {"type": "string", "enum": ["network", "write", "read"]},
                    "target": {"type": "string"}, "action": {"type": "string", "description": "Short description of the attempted action, without secrets."},
                    "private": {"type": "boolean", "description": "Also request private network addresses for this exact destination."}}, "required": ["kind", "target"]}})
