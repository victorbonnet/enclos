import asyncio
import importlib.util
import os
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "dashboard", Path(__file__).parents[1] / "dashboard.py"
)
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class DashboardTests(unittest.TestCase):
    def test_the_one_shot_adapter_removes_its_source_and_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "_enclos_dashboard.py"
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir()
            source.write_text("adapter")
            cache.write_bytes(b"bytecode")
            dashboard.remove_adapter(str(source))
            self.assertFalse(source.exists())
            self.assertFalse(cache.exists())
            # Cleanup also works with bytecode writing disabled or absent.
            dashboard.remove_adapter(str(source))

    def test_the_inherited_socket_and_authenticated_peer_reach_hermes(self):
        with tempfile.TemporaryDirectory() as directory:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(Path(directory) / "d"))
            listener.listen()
            fd = os.dup(listener.fileno())
            startup_sockets = []
            scopes = []
            responses = []

            class Server:
                async def startup(self, sockets=None):
                    startup_sockets.extend(sockets)

            class App:
                state = object()

                async def __call__(self, scope, receive, send):
                    scopes.append(scope)
                    if scope["type"] == "http":
                        await send(dict(type="http.response.start", headers=[]))

            app = App()
            web = types.ModuleType("web_server")
            web.app = app

            def start_server(**kwargs):
                self.assertEqual(
                    kwargs,
                    dict(host="127.0.0.1", port=0, open_browser=False, isolated=True),
                )

                async def check():
                    await Server().startup()
                    async def sent(message):
                        responses.append(message)
                    for kind, peer in [
                        ("http", None),
                        ("websocket", None),
                        ("websocket", ("192.0.2.1", 2000)),
                        ("lifespan", None),
                    ]:
                        await web.app(dict(type=kind, client=peer), None, sent)

                asyncio.run(check())

            web.start_server = start_server
            package = types.ModuleType("hermes_cli")
            package.web_server = web
            uvicorn = types.ModuleType("uvicorn")
            uvicorn.Server = Server
            with (
                patch.dict(sys.modules, {"uvicorn": uvicorn, "hermes_cli": package}),
                patch.dict(os.environ, {"ENCLOS_DASHBOARD_FD": str(fd)}),
                patch.object(sys, "argv", ["dashboard.py", "41003"]),
            ):
                dashboard.main()
                self.assertNotIn("ENCLOS_DASHBOARD_FD", os.environ)
                self.assertFalse(os.get_inheritable(fd))
                self.assertIs(web.app.state, app.state)
                self.assertEqual(web._read_bound_port(None, None), 41003)
            self.assertEqual(len(startup_sockets), 1)
            self.assertEqual(startup_sockets[0].family, socket.AF_UNIX)
            startup_sockets[0].close()
            self.assertEqual(scopes[0]["client"], ("127.0.0.1", 0))
            self.assertEqual(scopes[1]["client"], ("127.0.0.1", 0))
            self.assertEqual(scopes[2]["client"], ("192.0.2.1", 2000))
            self.assertIsNone(scopes[3]["client"])
            self.assertIn((b"referrer-policy", b"no-referrer"), responses[0]["headers"])

    def test_a_tcp_or_unbound_descriptor_is_refused_before_importing_hermes(self):
        for family in [socket.AF_INET, socket.AF_UNIX]:
            with socket.socket(family, socket.SOCK_STREAM) as listener:
                fd = os.dup(listener.fileno())
                with patch.dict(os.environ, {"ENCLOS_DASHBOARD_FD": str(fd)}):
                    with self.assertRaisesRegex(RuntimeError, "Unix stream listener"):
                        dashboard.main()


if __name__ == "__main__":
    unittest.main()
