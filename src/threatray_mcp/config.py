from enum import StrEnum
from typing import Any

from pydantic_settings import BaseSettings


class Transport(StrEnum):
    """MCP server transport.

    StrEnum: members are `str` subclasses, so `Transport.HTTP` IS the
    string `"http"`. Pass directly to FastMCP.run() and to f-strings
    without `.value`.
    """

    STDIO = "stdio"
    HTTP = "http"


class Settings(BaseSettings):
    # Required at runtime — no defaults. Pointing the URL at a wrong realm with the
    # wrong key is a hard-to-spot configuration mistake, so we force the operator to
    # specify both explicitly.
    api_url: str = ""
    api_key: str = ""
    log_level: str = "WARNING"

    # Transport: stdio (default) runs as a subprocess of an MCP client;
    # http runs as a standalone server on host:port (streamable-HTTP
    # endpoint /mcp). host/port are only consulted when transport == http.
    transport: Transport = Transport.STDIO
    host: str = "0.0.0.0"
    port: int = 8000

    model_config = {"env_prefix": "THREATRAY_"}

    def transport_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"transport": self.transport}
        if self.transport is Transport.HTTP:
            kwargs["host"] = self.host
            kwargs["port"] = self.port
        return kwargs

    @property
    def transport_address(self) -> str:
        if self.transport is Transport.HTTP:
            return f"http://{self.host}:{self.port}/mcp"
        return self.transport

    def get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"apikey {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }


settings = Settings()
