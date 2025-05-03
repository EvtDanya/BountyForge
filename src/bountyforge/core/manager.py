# import datetime
# import logging
# from typing import Any, Dict, List
# from celery import Celery
# from pymongo import MongoClient
# # from flask import current_app
# from bountyforge.config import settings
# # from bountyforge.core import get_module

# logger = logging.getLogger(__name__)

# celery = Celery(
#     "bountyforge",
#     broker=settings.backend.celery_broker_url,
# )
# # Mongo
# mongo = MongoClient(settings.backend.mongo_url)
# db = mongo.get_default_database()


# @celery.task(bind=True)
# def run_scan_task(self, request: Dict[str, Any]):
#     """
#     Фоновая задача запуска сканов.
#     self.request.id — уникальный job_id
#     """
#     targets: List[str] = request["targets"]
#     exclude: List[str] = request.get("exclude", [])
#     tools: List[str] = request["tools"]
#     params: Dict[str, Any] = request.get("params", {})

#     results = []
#     for tool in tools:
#         ModuleClass = get_module(tool)
#         if not ModuleClass:
#             logger.warning(f"No module class for tool '{tool}'")
#             continue

#         # инициализация модуля
#         mod = ModuleClass(
#             target=targets,
#             target_type=request.get("target_type"),
#             **params.get(tool, {})
#         )

#         # подписываемся на коллбэк для стрима (SSE)
#         def progress_callback(event: Dict[str, Any]):
#             # каждый раз, когда модуль что-то генерит, пушим в Redis pubsub
#             celery.backend.client.publish(f"scan:{self.request.id}", event)

#         mod.on_event = progress_callback

#         # запускаем
#         try:
#             res = mod.run()  # должен вернуть список dict или похожее
#             results.extend(res)
#         except Exception as e:
#             logger.exception(f"Error running {tool}")
#             results.append({
#                 "tool": tool, "status": "error", "error": str(e)
#             })

#     # сохраняем в Mongo
#     for entry in results:
#         entry.update({
#             "job_id":   self.request.id,
#             "timestamp": datetime.datetime.utcnow()
#         })
#         db.scan_results.insert_one(entry)

#     # финальное сообщение
#     celery.backend.client.publish(
#         f"scan:{self.request.id}",
#         {"event": "finished", "job_id": self.request.id}
#     )
#     return {"count": len(results)}

import pkgutil
import logging
from importlib import import_module
from typing import Type, Dict, Any
from bountyforge.core import Module

logger = logging.getLogger(__name__)


class ModuleManager:
    """
    Discovers all subclasses of Module in bountyforge.modules,
    keeps a registry and provides helper methods.
    """

    def __init__(self):
        self._modules: Dict[str, Type[Module]] = {}
        self._discover_modules()

    def _discover_modules(self) -> None:
        """
        Walk through bountyforge.modules package, импортим модули
        и регистрируем все классы-наследники Module.
        """
        import bountyforge.modules as modules_pkg

        for finder, name, ispkg in pkgutil.iter_modules(modules_pkg.__path__):
            full_name = f"bountyforge.modules.{name}"
            try:
                mod = import_module(full_name)
            except Exception as e:
                logger.error(f"Failed to import {full_name}: {e}")
                continue

            found = False
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if (
                    isinstance(cls, type)
                    and issubclass(cls, Module)
                    and cls is not Module
                ):
                    key = attr.lower().removesuffix("module")
                    self._modules[key] = cls
                    logger.debug(f"Registered module '{key}' -> {cls}")
                    found = True

            if not found:
                logger.debug(f"No Module subclass found in {full_name}")

    def list_modules(self) -> list[str]:
        """
        Return list of all available module keys
        """
        return sorted(self._modules.keys())

    def get_module(self, name: str) -> Type[Module] | None:
        """
        Return the module class by key (case-insensitive)
        """
        return self._modules.get(name.lower())

    def check_availability(self) -> dict[str, dict[str, Any]]:
        """
        For each registered module, call its check_availability()
        and collect results.
        """
        statuses: dict[str, dict[str, Any]] = {}
        for key, cls in self._modules.items():
            try:
                statuses[key] = cls.check_availability()
            except Exception as e:
                logger.exception(f"Availability check failed for {key}: {e}")
                statuses[key] = {"available": False, "version": None}
        return statuses


module_manager = ModuleManager()
