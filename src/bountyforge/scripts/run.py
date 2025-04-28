import logging
# import uvicorn

from bountyforge.config import settings
from bountyforge.main import create_app

logger = logging.getLogger("bountyforge")


def run() -> None:
    # options = {
    #     "bind": f"{settings.app.host}:{settings.app.port}",
    #     "workers": settings.app.workers,
    #     "threads": settings.app.threads,
    #     "timeout": settings.app.timeout,
    #     "loglevel": logging.getLevelName(settings.logging.level).lower(),
    #     "accesslog": "-",  # The Access log file to write to (- for stdout)
    #     "errorlog": settings.logging.file_path or "-",
    # }

    app = create_app()
    if app is None:
        logger.error("Failed to create app")
        return None

    app.run(
        host=settings.backend.host,
        port=settings.backend.port,
        debug=settings.backend.is_debug
    )
    # StandaloneGunicornApp(app, options).run()


if __name__ == "__main__":
    run()
