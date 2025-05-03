# bountyforge/tasks.py

from celery import Celery
from bountyforge.engine.engine import Engine
from bountyforge.modules.nmap_scanner import Module as NmapModule
from bountyforge.modules.subfinder import Module as SubfinderModule
# Импортируйте остальные модули по аналогии

import logging

logger = logging.getLogger(__name__)

celery_app = Celery('bountyforge', broker='redis://localhost:6379/0')


@celery_app.task
def run_scan_task(scan_params: dict) -> dict:
    """
    Asynchronously run a scan with specified parameters.
    scan_params может содержать:
      - target, target_type,
      - настройки для отдельных утилит (флаги, режимы),
      - список утилит для запуска (например, ['nmap', 'subfinder', ...])
    """
    # Создаем Engine
    engine = Engine()

    target = scan_params.get("target")
    target_type = scan_params.get("target_type", "single")

    # Пример: если пользователь выбрал nmap и subfinder
    if "nmap" in scan_params.get("tools", []):
        nmap_params = scan_params.get("nmap", {})
        nmap_module = NmapModule(
            scan_type=nmap_params.get("scan_type", "default"),
            target=target,
            target_type=target_type,
            additional_flags=nmap_params.get("additional_flags", [])
        )
        engine.register_module(nmap_module)

    if "subfinder" in scan_params.get("tools", []):
        subfinder_params = scan_params.get("subfinder", {})
        subfinder_module = SubfinderModule(
            target=target,
            target_type=target_type,
            additional_flags=subfinder_params.get("additional_flags", [])
        )
        engine.register_module(subfinder_module)

    # Добавьте другие модули по необходимости
    # Запуск всех модулей
    results = engine.run_all()

    # Сохраните результаты в базу или верните их
    return results
