"""Run Hermes's dashboard on a Unix listener already bound by enclos.

The descriptor is the only listening socket this process receives. Seatbelt
refuses TCP binds for this session, so a changed Hermes/Uvicorn startup
fails closed instead of publishing the browser token on TCP.
"""

import os
import socket
import sys


def remove_adapter(source):
    """The launcher imports this one-shot module inside Hermes's environment.

    Remove both files before serving, including the cache Python may have
    written while loading the module. A killed session leaves no adapter
    in the runtime checkout.
    """
    import importlib.util
    from pathlib import Path

    Path(importlib.util.cache_from_source(source)).unlink(missing_ok=True)
    Path(source).unlink(missing_ok=True)


def main():
    listener = socket.socket(fileno=int(os.environ.pop("ENCLOS_DASHBOARD_FD")))
    if (
        listener.family != socket.AF_UNIX
        or listener.type != socket.SOCK_STREAM
        or not listener.getsockname()
    ):
        listener.close()
        raise RuntimeError("enclos dashboard requires a Unix stream listener")
    listener.set_inheritable(False)
    port = int(sys.argv[1])

    import uvicorn
    from hermes_cli import web_server

    class LocalPeer:
        """The Unix peer is enclos, after its owner and capability checks.

        Uvicorn gives Unix connections no TCP client address. Supply the
        authenticated local boundary to Hermes's loopback WebSocket gate;
        never take that identity from a forwarded client header.
        """

        def __init__(self, app):
            self.app = app

        def __getattr__(self, name):
            return getattr(self.app, name)

        async def __call__(self, scope, receive, send):
            if scope["type"] in {"http", "websocket"} and not scope.get("client"):
                scope = dict(scope, client=("127.0.0.1", 0))

            async def private_response(message):
                if message["type"] == "http.response.start":
                    headers = [
                        (key, value)
                        for key, value in message.get("headers", [])
                        if key.lower() != b"referrer-policy"
                    ]
                    message = dict(
                        message, headers=headers + [(b"referrer-policy", b"no-referrer")]
                    )
                await send(message)

            await self.app(scope, receive, private_response)

    web_server.app = LocalPeer(web_server.app)

    startup = uvicorn.Server.startup

    async def on_inherited_socket(server, sockets=None):
        if sockets is not None:
            raise RuntimeError("Hermes supplied an unexpected listening socket")
        return await startup(server, sockets=[listener])

    uvicorn.Server.startup = on_inherited_socket
    # Hermes's TCP-ready helper indexes getsockname() as (host, port).
    # A Unix socket has a pathname instead. Give the runtime the host's
    # verified front port, never a port or URL printed by the sandbox.
    web_server._read_bound_port = lambda server, fallback: port
    web_server.start_server(
        host="127.0.0.1", port=0, open_browser=False, isolated=True
    )


if __name__ == "__main__":
    remove_adapter(__file__)
    main()
