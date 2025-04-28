import logging

from bountyforge.config import settings
from bountyforge.main import create_app

logger = logging.getLogger("bountyforge")


def run() -> None:
    app = create_app()
    if app is None:
        logger.error("Failed to create app")
        return None

    app.run(
        host=settings.backend.host,
        port=settings.backend.port,
        debug=settings.backend.is_debug
    )


if __name__ == "__main__":
    run()
