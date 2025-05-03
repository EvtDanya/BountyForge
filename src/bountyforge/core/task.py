import datetime
import logging
from typing import Dict, Any
from celery import Celery
from pymongo import MongoClient

from bountyforge.config import settings
from bountyforge.core import module_manager
from bountyforge.core.module_base import TargetType, ScanType

logger = logging.getLogger(__name__)

# Настраиваем Celery
celery = Celery(
    "bountyforge",
    broker=settings.backend.celery_broker_url,
)
# Настраиваем MongoDB
mongo = MongoClient(settings.backend.mongo_url)
db = mongo.get_default_database()


@celery.task(bind=True)
def run_scan_task(self, request: Dict[str, Any]):
    """
    Фоновая задача запуска сканов.
    self.request.id — уникальный job_id
    """
    targets = request["target"]          # уже отфильтрованные
    exclude = request.get("exclude", []) # можно далее не учитывать или применять
    tools = request["tools"]           # ['nmap','nuclei',...]
    params = request.get("params", {})  # словарь с ключами по инструментам

    results = []
    for tool in tools:
        ModuleClass = module_manager.get_module(tool)
        if not ModuleClass:
            logger.warning(f"No module class for '{tool}'")
            continue

        # Собираем kwargs для конструктора
        init_kwargs: Dict[str, Any] = {
            "target": targets,
            "target_type": TargetType(request.get("target_type", "multiple")),
        }
        # если есть кастомный scan_type для этого инструмента
        if slot := params.get(tool, {}).get("scan_type"):
            init_kwargs["scan_type"] = ScanType(slot)
        # дополнительные флаги
        if flags := params.get(tool, {}).get("additional_flags"):
            init_kwargs["additional_flags"] = flags
        # для Nuclei: templates_dir
        if tool == "nuclei" and (t_dir := params["nuclei"].get("templates_dir")):
            init_kwargs["templates_dir"] = t_dir

        # Инициализируем модуль
        mod = ModuleClass(**init_kwargs)

        # Запускаем сканирование
        try:
            res = mod.run()  # возвращает dict с успехом/ошибкой и выводом
            entry = {
                "tool": tool,
                "job_id": self.request.id,
                "timestamp": datetime.datetime.utcnow(),
                **res
            }
            results.append(entry)
        except Exception as e:
            logger.exception(f"Error running {tool}")
            results.append({
                "tool": tool,
                "job_id": self.request.id,
                "timestamp": datetime.datetime.utcnow(),
                "error": str(e),
                "success": False
            })

    if results:
        db.scan_results.insert_many(results)

    return {"job_id": self.request.id, "count": len(results)}
