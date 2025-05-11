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
        Walk through bountyforge.modules package, import modules
        and register classes from Module.
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
