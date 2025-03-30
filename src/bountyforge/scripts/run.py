import logging
import uvicorn

from bountyforge.config import settings
from bountyforge.main import create_app

logger = logging.getLogger("bountyforge")


def run() -> None:
    logger.info("Starting web app...")

    options = {
        "bind": f"{settings.app.host}:{settings.app.port}",
        "workers": settings.app.workers,
        "threads": settings.app.threads,
        "timeout": settings.app.timeout,
        "loglevel": logging.getLevelName(settings.logging.level).lower(),
        "accesslog": "-",  # The Access log file to write to (- for stdout)
        "errorlog": settings.logging.file_path or "-",
    }

    app = create_app()
    app.run()
    # StandaloneGunicornApp(app, options).run()


if __name__ == "__main__":
    run()
