import importlib
import logging
from typing import Dict, List

from bountyforge.config import ModuleConfig  # Assumes ModuleConfig is defined in your config.py

logger = logging.getLogger(__name__)

class ModuleManager:
    """
    ModuleManager is responsible for dynamically loading and registering pentest modules.
    """
    def __init__(self, modules_config: List[ModuleConfig]):
        self.modules_config = modules_config
        self.modules: Dict[str, object] = {}

    def load_modules(self) -> None:
        """
        Loads modules based on the configuration.
        For each enabled module, attempts to import it from the bountyforge.modules package,
        looks for a class named 'Module', and instantiates it using configuration parameters.
        """
        for mod_conf in self.modules_config:
            if mod_conf.enabled:
                module_path = f"bountyforge.modules.{mod_conf.name}"
                try:
                    module = importlib.import_module(module_path)
                    # It is expected that the module contains a class named 'Module'
                    # that implements the base interface from bountyforge/core/module_base.py.
                    module_class = getattr(module, "Module", None)
                    if module_class is None:
                        logger.warning(f"Module '{mod_conf.name}' does not have a 'Module' class. Skipping.")
                        continue

                    # Initialize the module with configuration parameters.
                    instance = module_class(**mod_conf.config)
                    self.modules[mod_conf.name] = instance
                    logger.info(f"Module '{mod_conf.name}' loaded successfully.")
                except ModuleNotFoundError:
                    logger.error(f"Module '{mod_conf.name}' not found at path {module_path}.")
                except Exception as e:
                    logger.error(f"Error loading module '{mod_conf.name}': {e}")

    def get_module(self, name: str):
        """
        Returns the module instance by name if it has been loaded.
        
        :param name: The name of the module.
        :return: The module instance or None if not loaded.
        """
        return self.modules.get(name)
