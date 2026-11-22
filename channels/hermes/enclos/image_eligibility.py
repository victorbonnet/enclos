"""Image eligibility at arrival, using the receiving conversation's runtime."""


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
