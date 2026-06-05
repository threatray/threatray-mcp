import logging

from .config import settings
from .log import configure_logging
from .server import create_server

log = logging.getLogger(__name__)


def main():
    configure_logging()
    log.info("Starting threatray-mcp on %s", settings.transport_address)
    create_server().run(**settings.transport_kwargs())


if __name__ == "__main__":
    main()
