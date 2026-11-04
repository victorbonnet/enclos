"""enclos's channel for Hermes: the mobile app, through the host's bridge.

`register` imports the Hermes side only when Hermes calls it, so the
protocol and the outbox can be tested without Hermes installed.
"""


def register(ctx) -> None:
    from .adapter import register as register_platform

    register_platform(ctx)
