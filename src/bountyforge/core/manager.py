import datetime
import logging
from typing import Any, Dict, List
from celery import Celery
from pymongo import MongoClient
# from flask import current_app
from bountyforge.config import settings
# from bountyforge.core import get_module

logger = logging.getLogger(__name__)

celery = Celery(
    "bountyforge",
    broker=settings.backend.celery_broker_url,
)
# Mongo
mongo = MongoClient(settings.backend.mongo_url)
db = mongo.get_default_database()


@celery.task(bind=True)
def run_scan_task(self, request: Dict[str, Any]):
    """
    Фоновая задача запуска сканов.
    self.request.id — уникальный job_id
    """
    targets: List[str] = request["targets"]
    exclude: List[str] = request.get("exclude", [])
    tools: List[str] = request["tools"]
    params: Dict[str, Any] = request.get("params", {})

    results = []
    for tool in tools:
        ModuleClass = get_module(tool)
        if not ModuleClass:
            logger.warning(f"No module class for tool '{tool}'")
            continue

        # инициализация модуля
        mod = ModuleClass(
            target=targets,
            target_type=request.get("target_type"),
            **params.get(tool, {})
        )

        # подписываемся на коллбэк для стрима (SSE)
        def progress_callback(event: Dict[str, Any]):
            # каждый раз, когда модуль что-то генерит, пушим в Redis pubsub
            celery.backend.client.publish(f"scan:{self.request.id}", event)

        mod.on_event = progress_callback

        # запускаем
        try:
            res = mod.run()  # должен вернуть список dict или похожее
            results.extend(res)
        except Exception as e:
            logger.exception(f"Error running {tool}")
            results.append({
                "tool": tool, "status": "error", "error": str(e)
            })

    # сохраняем в Mongo
    for entry in results:
        entry.update({
            "job_id":   self.request.id,
            "timestamp": datetime.datetime.utcnow()
        })
        db.scan_results.insert_one(entry)

    # финальное сообщение
    celery.backend.client.publish(
        f"scan:{self.request.id}",
        {"event": "finished", "job_id": self.request.id}
    )
    return {"count": len(results)}
