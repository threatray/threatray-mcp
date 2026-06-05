from importlib.metadata import PackageNotFoundError, version

from .server import create_server

try:
    __version__ = version("threatray-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0+local"

__all__ = ["__version__", "create_server"]
