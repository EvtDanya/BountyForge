"""
Engine for modules coordination
"""
import logging
from typing import List
from core.module_base import Module

logger = logging.getLogger(__name__)


class Engine:
    def __init__(self):
        self.modules: List[Module] = []

    def register_module(self, module: Module) -> None:
        self.modules.append(module)
        logger.info(f"Registered module: {module.__class__.__name__}")

    def run(self, target: str) -> None:
        logger.info(f"Running modules for target: {target}")
        for module in self.modules:
            try:
                result = module.run(target)
                logging.info(
                    f"Результат модуля {module.__class__.__name__}: {result}"
                )
                # Здесь можно добавить передачу результатов в анализ или в веб-панель
            except Exception as e:
                logger.error(
                    f"Ошибка в модуле {module.__class__.__name__}: {e}"
                )
