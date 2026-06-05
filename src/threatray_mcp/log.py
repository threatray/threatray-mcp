"""Logging configuration.

On stdio transport, stdout carries JSON-RPC frames — any print/log to stdout will
corrupt the protocol. Logs must go to stderr. This module installs a stderr handler
on the `threatray_mcp` logger, configured by the `THREATRAY_LOG_LEVEL` env var
(default: WARNING). Call `configure_logging()` from `__main__.main()` before
`mcp.run("stdio")`.
"""

import logging
import sys

from .config import settings


def configure_logging() -> None:
    """Install a stderr-only handler on the threatray_mcp logger."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    root = logging.getLogger("threatray_mcp")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())
    root.propagate = False
