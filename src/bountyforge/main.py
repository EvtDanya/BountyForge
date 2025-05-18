import logging
import flask
from flask_cors import CORS
# import gunicorn.app.base

from . import utils
from .config import settings
from .api import config_api, jwt

logger = logging.getLogger('bountyforge')

utils.init_logging(logger)

# import uvicorn
# uvicorn.run(
#     "bountyforge.main:app",
#     host=settings.app.host,
#     port=settings.app.port,
#     reload=True
# )

# class StandaloneGunicornApp(gunicorn.app.base.BaseApplication):
#     def __init__(self, app, options=None):
#         self.options = options or {}
#         self.application = app
#         super().__init__()

#     def load_config(self):
#         config = {
#             key: value for key, value in self.options.items()
#             if key in self.cfg.settings and value is not None
#         }
#         for key, value in config.items():
#             self.cfg.set(key.lower(), value)

#     def load(self):
#         return self.application


def is_correct_config() -> bool:
    if not (
        settings.backend.auth_user == settings.frontend.auth_user
        and settings.backend.auth_pass == settings.frontend.auth_pass
    ):
        logger.warning(
            "Backend and Frontend are using not the same user. "
            "This may cause issues with the web app."
        )
        return False

    if not (
        settings.backend.session_secret_key ==
            settings.frontend.session_secret_key
    ):
        logger.warning(
            "Backend and Frontend are using not the same secret key. "
            "This may cause issues with the web app."
        )
        return False

    if not (
        settings.backend.session_lifetime ==
            settings.frontend.session_lifetime
    ):
        logger.warning(
            "Backend and Frontend are using not the same session lifetime. "
            "This may cause issues with the web app."
        )
        return False

    return True


def create_app() -> flask.Flask | None:
    if not is_correct_config():
        return None

    logger.info(
        f"Starting backend server on: "
        f"{settings.backend.host}:{settings.backend.port}"
    )
    app = flask.Flask(__name__)
    app.config['JWT_SECRET_KEY'] = settings.backend.session_secret_key

    jwt.init_app(app)

    frontend_origins = [
        f'http://{settings.backend.frontend_host}:{settings.frontend.port}',
        f'http://127.0.0.1:{settings.frontend.port}',
        f'http://localhost:{settings.frontend.port}'
    ]

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": frontend_origins,  # '*', # f"http://{settings.backend.frontend_host}:{settings.frontend.port}",  # noqa
                "allow_headers": ["Authorization", "Content-Type"],
                "supports_credentials": True
            }
        }
    )
    app.register_blueprint(config_api)

    return app


if __name__ == "__main__":
    app = create_app()
    if app is None:
        logger.error("Failed to create app")
        exit(1)

    app.run(
        host=settings.backend.host,
        port=settings.backend.port,
        debug=settings.backend.is_debug
    )
