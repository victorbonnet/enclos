"""Image eligibility at arrival, using the receiving conversation's runtime."""
import contextlib
from pathlib import Path


def _hello_scope(adapter, source):
    """For the hello's check only (no `source`), the agent's own profile scope:
    a multiplexed gateway refuses a provider's credentials (such as Codex's base
    URL) read outside one, and the hello runs on a worker thread with no turn
    around it, so it would always say no. A conversation's check at arrival
    already runs in its routed profile's scope (`producer_scope`), which may
    not be the adapter's: it is kept. Hermes without the helper, or an adapter
    with no home, runs as is."""
    home = getattr(adapter, "_conversation_home", None)
    if source is not None or home is None:
        return contextlib.nullcontext()
    try:
        from gateway.run import _profile_runtime_scope
    except ImportError:
        return contextlib.nullcontext()
    return _profile_runtime_scope(Path(home))


def available(adapter, source=None):
    try:
        from hermes_cli.config import load_config
        from agent.image_routing import decide_image_input_mode
        from agent.auxiliary_client import scoped_runtime_main
        from tools.vision_tools import check_video_requirements
        runner = getattr(adapter._message_handler, "__self__", None)
        # This is the gateway's session resolver used by image enrichment itself.
        # A failed resolution is unknown; never fall back to process tool context.
        resolve = getattr(runner, "_resolve_session_agent_runtime", None)
        if not callable(resolve):
            return False
        with _hello_scope(adapter, source):
            cfg = load_config()
            model, runtime = resolve(source=source, user_config=cfg)
            if not isinstance(model, str) or not model or not isinstance(runtime, dict):
                return False
            provider = runtime.get("provider")
            if not isinstance(provider, str) or not provider:
                return False
            with scoped_runtime_main({**runtime, "model": model}):
                mode = decide_image_input_mode(provider, model, cfg,
                                               requested_provider=runtime.get("requested_provider", ""))
                return mode == "native" or check_video_requirements() is True
    except Exception:
        return False
