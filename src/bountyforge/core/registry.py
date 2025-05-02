import pkgutil
import importlib
from typing import Dict, Type
from bountyforge.core import Module

_registry: Dict[str, Type[Module]] = {}


def discover_modules(package):
    """
    Пробегает по всем подпакетам package.modules,
    импортирует их и регистрирует класс-наследник Module.
    """
    pkg = importlib.import_module(package)
    for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"{package}.{name}")
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, Module)
                and obj is not Module
            ):
                _registry[obj.__name__.lower()] = obj


def get_module(name: str):
    return _registry.get(name.lower())


discover_modules("bountyforge.modules")
