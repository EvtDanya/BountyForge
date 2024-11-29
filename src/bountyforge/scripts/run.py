import logging

from dockertrap.config import settings
from dockertrap.main import create_app, StandaloneGunicornApp

logger = logging.getLogger("bountyforge")


def run():
    logger.info("Starting app with Gunicorn...")

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
    StandaloneGunicornApp(app, options).run()


if __name__ == "__main__":
    run()
