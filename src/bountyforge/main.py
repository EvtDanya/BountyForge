import logging
import flask
import gunicorn.app.base

from . import utils
from .config import settings

from dockertrap.routes import main_router

logger = logging.getLogger('bountyforge')

utils.init_logging(logger)


class StandaloneGunicornApp(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def create_app():
    logger.info(
        f'Starting server on: {settings.app.host}:{settings.app.port}'
    )

    app = flask.Flask(__name__)
    app.register_blueprint(main_router)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=settings.app.host,
        port=settings.app.port
    )
