"""End-to-end test for the standalone HTTP transport.

Boots `create_server()` over streamable-HTTP on a free localhost port in a
background task, connects with `fastmcp.Client`, and confirms the tool
catalogue is reachable. Validates the deployment path used when the server
runs as its own container instead of as a stdio subprocess.
"""

import asyncio
import os
import socket
import unittest

# Env vars must be set BEFORE importing threatray_mcp — pydantic-settings reads
# them at Settings() construction time, which happens at module import.
os.environ.setdefault("THREATRAY_API_URL", "https://api.threatray.test")
os.environ.setdefault("THREATRAY_API_KEY", "test-key")
# Bypass any HTTP_PROXY (corporate Squid in CI) for loopback. httpx doesn't
# support CIDR in NO_PROXY (so the container's `127.0.0.0/8` entry is ignored)
# — force the literal IP. Overwrite, don't setdefault: the container value
# already exists but its CIDR form is useless to httpx.
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ["no_proxy"] = "127.0.0.1,localhost"

from fastmcp import Client

from threatray_mcp.server import create_server


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            _, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise TimeoutError(f"Server did not start listening on {host}:{port} within {timeout}s")


class TestHttpTransport(unittest.IsolatedAsyncioTestCase):
    async def test_list_tools_over_http(self):
        """Boot the server in HTTP mode and confirm a representative tool is
        reachable through the fastmcp Client. Validates the full deployment
        path — same code is exercised over the HTTP transport instead of
        stdio, the catalogue we surface in stdio mode is identical here.
        """
        port = _pick_free_port()
        mcp = create_server()

        server_task = asyncio.create_task(
            mcp.run_async(transport="http", host="127.0.0.1", port=port, show_banner=False)
        )

        try:
            await _wait_for_port("127.0.0.1", port)

            async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                tools = await client.list_tools()

            tool_names = {t.name for t in tools}
            self.assertGreater(len(tool_names), 0, "expected at least one tool")
            self.assertIn("threatray_search", tool_names)
        finally:
            server_task.cancel()
            try:
                await server_task
            except (asyncio.CancelledError, Exception):
                # Server task is being torn down; swallow whatever its
                # last-gasp shutdown raises so the test result is clean.
                pass


if __name__ == "__main__":
    unittest.main()
