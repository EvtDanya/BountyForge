"""
Base module for all modules using the Template Method pattern
with integrated command execution
"""

from typing import Any, Dict, List, Union
import subprocess
import logging
import enum
import os

logger = logging.getLogger(__name__)


class ScanType(enum.Enum):
    """
    Type of scan to be performed
    """

    DEFAULT = "default"
    AGGRESSIVE = "aggressive"
    FULL = "full"
    RECON = "recon"
    LIVE = "live"


class TargetType(enum.Enum):
    """
    Type of target input.
    SINGLE = a single URL/IP (string)
    MULTIPLE = a list of targets
    FILE = a file path containing targets, one per line
    """
    SINGLE = "single"
    MULTIPLE = "multiple"
    FILE = "file"


class Module():
    """
    Base class for all modules with scans
    """

    scan_type: ScanType = ScanType.DEFAULT
    target: Union[str, List[str]] = None
    target_type: TargetType = TargetType.SINGLE
    additional_flags: List[str] = None

    def __init__(
        self,
        scan_type: ScanType,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        additional_flags: List[str] = None
    ) -> None:
        """
        Initialize the module

        :param scan_type: Type of scan to be performed.
        :param target: The target(s)
        :param target_type: The type of target input.
        :param additional_flags: Additional command-line flags.
        """
        self.scan_type = scan_type
        self.target = target
        self.target_type = target_type
        self.additional_flags = additional_flags\
            if additional_flags is not None else []

    def _prepare_target(self) -> str:
        """
        Validate the target based on target_type
            and prepare a single string to pass to the command

        For MULTIPLE targets, joins the list with a comma
        For FILE, the file path is returned as is
        For SINGLE, validates that target is a string

        :return: Prepared target as a string
        :raises ValueError: If the target does not match the expected type
        """
        if self.target_type == TargetType.SINGLE:
            if not isinstance(self.target, str):
                logger.error(
                    "SINGLE target type requires a string"
                )
                raise ValueError(
                    "Invalid target type for SINGLE"
                )
            return self.target.strip()
        elif self.target_type == TargetType.MULTIPLE:
            if not isinstance(self.target, list):
                logger.error(
                    "MULTIPLE target type requires a list of strings"
                )
                raise ValueError(
                    "Invalid target type for MULTIPLE"
                )
            return ",".join(map(str, self.target)).strip()
        elif self.target_type == TargetType.FILE:
            if (
                not (
                    isinstance(self.target, str)
                    and os.path.isfile(self.target)
                )
            ):
                logger.error(
                    "FILE target type requires a valid file path"
                )
                raise ValueError(
                    "Invalid target file path"
                )
            return self.target
        else:
            logger.error(
                "Unknown target type specified"
            )
            raise ValueError(
                "Unknown target type"
            )

    def pre_run(self, target_str: str) -> None:
        """
        Common pre-run actions such as logging and target validation

        :param target_str: The prepared target string
        """
        logger.info(
            f"[{self.__class__.__name__}] Preparing to run module "
            f"for target(s): {target_str}"
        )

    def _build_command(self, target_str: str) -> List[str]:
        """
        Build the command to be executed for the given prepared target

        Must be implemented by concrete modules

        :param target_str: The prepared target string
        :return: A list of command arguments
        """
        logger.info(
            f"[{self.__class__.__name__}] Building command for target: "
            f"{target_str} with scan type: {self.scan_type.value}"
        )

    def _execute_command(self, command: List[str]) -> Dict[str, Any]:
        """
        Executes a system command using subprocess.run

        This method encapsulates the logic for running shell commands,
            capturing output, and handling exceptions consistently

        :param command: A list of command arguments
        :return: A dictionary containing 'output' with the command result
        if successful, or 'error' with error message if an exception occurs
        """
        try:
            logger.debug(
                f"[{self.__class__.__name__}] Running command: "
                f"{' '.join(command)}"
            )
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )

            logger.info(
                "[i] Command executed successfully"
            )
            return {"output": process.stdout.strip()}
        except subprocess.CalledProcessError as ex:
            logger.error(
                f"[!] Command '{' '.join(command)}' failed with error: {ex}"
            )
            return {"error": str(ex)}
        except Exception as ex:
            logger.exception(
                f"[ERR] Unexpected exception while executing command: "
                f"{' '.join(command)}. Exception: {ex}"
            )
            return {
                "error": f"Unexpected exception: {ex}"
            }

    def _post_run(self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Common post-run actions (e.g., logging, result formatting)

        Override this method in a subclass
            for additional result handling if needed

        :param target: The target address or domain
        :param result: The raw result dictionary from the execute method
        :return: A dictionary containing the final processed results
        """
        logger.info(f"[i] Completed execution for target: {target}")

        return result

    def run(self) -> Dict[str, Any]:
        """
        Template method that defines the skeleton for executing the module

        :return: A dictionary with the final result
        """
        try:
            target_str = self._prepare_target()
            self._pre_run(target_str)
            command = self._build_command(target_str)
            result = self._execute_command(command)
            final_result = self._post_run(target_str, result)
            return final_result
        except Exception as ex:
            logger.exception(
                f"[ERR] An unexpected error occurred, "
                f"target '{self.target}': {ex}"
            )
            return {"error": f"Unexpected error: {ex}"}

    def check_availability(self) -> bool:
        """
        Check if the module is available for use

        :return: True if the module is available, False otherwise
        """
        # Here we can check for dependencies or other conditions
        # For now, we assume the module is always available
        return True
