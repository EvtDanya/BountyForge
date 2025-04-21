import logging
import flask
from flask_cors import CORS
from datetime import timedelta
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


def create_app() -> flask.Flask:
    logger.info(
        f"Starting backend server on: "
        f"{settings.backend.host}:{settings.backend.port}"
    )
    app = flask.Flask(__name__)
    app.config['JWT_SECRET_KEY'] = settings.backend.session_secret_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] =\
        timedelta(hours=settings.backend.session_lifetime)

    jwt.init_app(app)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": f"http://{settings.frontend.host}:{settings.frontend.port}",  # noqa
                "allow_headers": ["Authorization", "Content-Type"],
                "supports_credentials": True
            }
        }
    )
    app.register_blueprint(config_api)

    # # Регистрируем сканирующие модули через ModuleManager
    # module_manager = ModuleManager(settings.scanners)
    # module_manager.load_modules()

    # # Опционально: можем создать и настроить Engine
    # для последовательного запуска модулей
    # engine = Engine()
    # for module in module_manager.modules.values():
    #     engine.register_module(module)

    # # Запускаем все модули для тестового target (например, "example.com")
    # engine.run("example.com")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host=settings.backend.host,
        port=settings.backend.port,
        debug=settings.backend.is_debug
    )
