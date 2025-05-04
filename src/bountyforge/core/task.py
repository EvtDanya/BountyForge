import datetime
import logging
import json
from typing import Any, Dict, List

from celery import Celery
from pymongo import MongoClient
import redis

from bountyforge.config import settings
from bountyforge.core import module_manager
from bountyforge.core.module_base import TargetType, ScanType

logger = logging.getLogger(__name__)

celery = Celery(
    "bountyforge",
    broker=settings.backend.celery_broker_url,
)

mongo = MongoClient(settings.backend.mongo_url)
db = mongo.get_default_database()

redis_client = redis.Redis.from_url(settings.backend.celery_broker_url)


@celery.task(bind=True)
def run_scan_task(self, request: Dict[str, Any]):
    """
    Фоновая задача запуска сканов
    """
    targets: List[str] = request["target"]
    tools: List[str] = request["tools"]
    params: Dict[str, Any] = request.get("params", {})

    logger.info(f"Starting scan task with ID: {self.request.id}")
    logger.info(f"Targets: {targets}")
    logger.info(f"Tools: {tools}")

    channel = f"scan:{self.request.id}"
    db.scan_jobs.update_one(
        {"job_id": self.request.id},
        {"$set": {"status": "running"}}
    )
    redis_client.publish(channel, json.dumps({
        "event": "started",
        "job_id": self.request.id
    }))

    all_results: List[Dict[str, Any]] = []

    for tool in tools:
        ModuleClass = module_manager.get_module(tool)
        if not ModuleClass:
            logger.warning(f"No module class for '{tool}'")
            continue

        init_kwargs: Dict[str, Any] = {
            "target":       targets,
            "target_type":  TargetType(request.get("target_type", "multiple")),
        }
        if slot := params.get(tool, {}).get("scan_type"):
            init_kwargs["scan_type"] = ScanType(slot)
        if flags := params.get(tool, {}).get("additional_flags"):
            init_kwargs["additional_flags"] = flags
        if tool == "nuclei" and (td := params["nuclei"].get("templates_dir")):
            init_kwargs["templates_dir"] = td

        mod = ModuleClass(**init_kwargs)

        try:
            res = mod.run()
            logger.info(f"[{tool}] raw results: {res}")

            if not isinstance(res, list):
                res = [res]

            if isinstance(res, dict) and "result" in res:
                output_lines = res["result"].strip().split("\n")
                for line in output_lines:
                    payload = {
                        "event": "result",
                        "tool": tool,
                        "job_id": self.request.id,
                        "output": line,
                    }
                    redis_client.publish(channel, json.dumps(payload))
                    all_results.append({
                        **payload,
                        "timestamp": datetime.datetime.now()
                    })
            else:
                logger.warning(f"[{tool}] Unexpected result format: {res}")

        except Exception as e:
            logger.exception(f"Error running {tool}")
            err_payload = {
                "event": "error",
                "tool": tool,
                "msg": str(e),
                "job_id": self.request.id
            }
            redis_client.publish(channel, json.dumps(err_payload))

            all_results.append({
                "tool":      tool,
                "job_id":    self.request.id,
                "timestamp": datetime.datetime.now(),
                "error":     str(e),
                "success":   False
            })

    if all_results:
        db.scan_results.insert_many(all_results)
        logger.info(
            f"Inserted {len(all_results)} records for job {self.request.id}"
        )
    db.scan_jobs.update_one(
        {"job_id": self.request.id},
        {"$set": {"status": "finished"}}
    )

    redis_client.publish(channel, json.dumps({
        "event": "finished",
        "job_id": self.request.id
    }))

    return {"job_id": self.request.id, "count": len(all_results)}
