import logging
import flask
# import gunicorn.app.base

from . import utils
from .config import settings

from fastapi import FastAPI
# from bountyforge.api import endpoints

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


def create_app():
    logger.info(f"Starting server on: {settings.app.host}:{settings.app.port}")
    app = flask.Flask(__name__)

    # Регистрируем сканирующие модули через ModuleManager
    module_manager = ModuleManager(settings.scanners)
    module_manager.load_modules()

    # Опционально: можем создать и настроить Engine для последовательного запуска модулей
    engine = Engine()
    for module in module_manager.modules.values():
        engine.register_module(module)

    # Запускаем все модули для тестового target (например, "example.com")
    engine.run("example.com")

    # Далее можно зарегистрировать blueprints или API-эндпоинты для веб-интерфейса
    return app


def create_app():
    logger.info(
        f'Starting server on: {settings.app.host}:{settings.app.port}'
    )

    app = flask.Flask(__name__)
    # app.register_blueprint(main_router)

    return app


# if __name__ == "__main__":
#     app = create_app()
#     app.run(
#         host=settings.app.host,
#         port=settings.app.port
#     )

# app = FastAPI(title="BountyForge Web PenTest Backend")

# app.include_router(endpoints.router)

if __name__ == "__main__":
    app = create_app()
    app.run()
