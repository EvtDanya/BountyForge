# src/bountyforge/core/task.py
import datetime
import logging
import json
from typing import Dict, Any
from celery import Celery
from pymongo import MongoClient
import redis
from bountyforge.config import settings
from bountyforge.core import module_manager
from bountyforge.core.module_base import TargetType, ScanType

logger = logging.getLogger(__name__)

# Celery
celery = Celery("bountyforge", broker=settings.backend.celery_broker_url)

# MongoDB
mongo = MongoClient(settings.backend.mongo_url)
db = mongo.get_default_database()

# Redis—для Pub/Sub (используем отдельный клиент, чтобы не путать с Celery)
redis_client = redis.Redis.from_url(settings.backend.celery_broker_url)


@celery.task(bind=True)
def run_scan_task(self, request: Dict[str, Any]):
    """
    Background scan task. Publishes events to Redis channel scan:<job_id>
    """
    job_id = self.request.id
    channel = f"scan:{job_id}"

    def publish(event: Dict[str, Any]):
        redis_client.publish(channel, json.dumps(event))

    # сообщаем клиенту, что стартовали
    publish({"event": "started", "job_id": job_id})

    targets = request["target"]
    tools   = request["tools"]
    params  = request.get("params", {})

    results = []
    for tool in tools:
        ModuleClass = module_manager.get_module(tool)
        if not ModuleClass:
            publish({"event": "error", "tool": tool, "msg": "Module not found"})
            continue

        # собираем init-args…
        init_kwargs: Dict[str, Any] = {
            "target": targets,
            "target_type": TargetType(request.get("target_type", "multiple")),
        }
        if slot := params.get(tool, {}).get("scan_type"):
            init_kwargs["scan_type"] = ScanType(slot)
        if flags := params.get(tool, {}).get("additional_flags"):
            init_kwargs["additional_flags"] = flags
        if tool == "nuclei" and (t_dir := params["nuclei"].get("templates_dir")):
            init_kwargs["templates_dir"] = t_dir

        mod = ModuleClass(**init_kwargs)

        # небольшой callback чтобы модули внутри тоже могли пушить прогресс
        def on_event(evt: Dict[str, Any]):
            evt.update({"tool": tool})
            publish(evt)
        mod.on_event = on_event

        # запускаем
        try:
            res = mod.run()  # dict с результатом
            evt = {"event": "result", "tool": tool, **res}
            publish(evt)
            results.append({**evt, "job_id": job_id, "timestamp": datetime.datetime.utcnow()})
        except Exception as e:
            logger.exception(f"Error running {tool}")
            publish({"event": "error", "tool": tool, "msg": str(e)})

    # сохраняем все результаты в Mongo
    if results:
        logger.info(results)
        db.scan_results.insert_many(results)

    # завершающее сообщение
    publish({"event": "finished", "job_id": job_id})
    return {"job_id": job_id, "count": len(results)}
