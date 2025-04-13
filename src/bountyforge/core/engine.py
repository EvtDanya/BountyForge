import logging
from typing import List
from bountyforge.core.module_base import Module

logger = logging.getLogger(__name__)


class Engine:
    """
    Engine for modules coordination

    Responsible for registering and running
        all scan modules for a given target
    """
    def __init__(self):
        self.modules: List[Module] = []

    def register_module(self, module: Module) -> None:
        """
        Registers a module for scanning

        :param module: An instance of a module
            (subclass of Module) to register
        """
        self.modules.append(module)
        logger.info(
            f"[i] Registered module: {module.__class__.__name__}"
        )

    def run(self, target: str) -> None:
        """
        Runs each registered module for the given target.

        :param target: The target address or domain.
        """
        logger.info(f"Running modules for target: {target}")
        for module in self.modules:
            try:
                result = module.run(target)
                logger.info(
                    f"[i] Module {module.__class__.__name__} result: {result}"
                )
                #! Здесь можно добавить передачу результатов в систему анализа или веб-панель
            except Exception as e:
                logger.error(
                    f"[ERR] Error in module {module.__class__.__name__}: {e}"
                )
