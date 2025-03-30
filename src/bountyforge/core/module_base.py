"""
Base module for all modules using Template Method pattern.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

class Module(ABC):
    def run(self, target: str) -> Dict[str, Any]:
        """
        Template method that defines the skeleton of executing a module.
        It calls pre_run, then execute, and finally post_run.
        
        :param target: The target address or domain.
        :return: A dictionary containing the results.
        """
        self.pre_run(target)
        result = self.execute(target)
        final_result = self.post_run(target, result)
        return final_result

    def pre_run(self, target: str) -> None:
        """
        Common pre-run actions (e.g., logging, validation, etc.).
        
        :param target: The target address or domain.
        """
        # Common logic before executing the module.
        pass

    @abstractmethod
    def execute(self, target: str) -> Dict[str, Any]:
        """
        Concrete modules must implement this method to perform the actual execution.
        
        :param target: The target address or domain.
        :return: A dictionary with the execution result.
        """
        pass

    def post_run(self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Common post-run actions (e.g., logging, result formatting).
        
        :param target: The target address or domain.
        :param result: The result from the execute method.
        :return: A dictionary with the final result.
        """
        # Common logic after executing the module.
        return result
