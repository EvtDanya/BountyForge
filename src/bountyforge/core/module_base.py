"""
Base module for all modules using the Template Method pattern
with integrated command execution
"""

from typing import Any, Dict, List, Union, Optional
import subprocess
import logging
import enum
import os
import shutil
import re

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
    SUBDOMAIN = "subdomain"
    DIRECTORY = "directory"


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
    timeout: int = 7200  # 2 hours
    binary_name: str = ""
    headers: dict = None

    def __init__(
        self,
        scan_type: ScanType,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        exclude: List[str] = None,
        additional_flags: List[str] = None,
        headers: dict = None,
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
        self.additional_flags = additional_flags or []
        self.headers = headers or {}
        self.exclude = exclude or []

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
            if not self.target:
                raise ValueError("No valid targets provided")
            return self.target.strip()
        elif self.target_type == TargetType.MULTIPLE:
            if not isinstance(self.target, list):
                logger.error(
                    "MULTIPLE target type requires a list of strings"
                )
                raise ValueError(
                    "Invalid target type for MULTIPLE"
                )
            if not self.target:
                raise ValueError("No valid targets provided")
            # print(f'len {len(self.target)}')
            # if len(self.target) == 1:
            #     print(str(t).strip() for t in self.target)
            #     return [str(t).strip() for t in self.target]
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

    def _pre_run(self, target_str: str) -> None:
        """
        Common pre-run actions such as logging and target validation

        :param target_str: The prepared target string
        """
        logger.info(
            f"[{self.__class__.__name__}] Preparing to run module "
            f"for target(s): {target_str}"
        )

    def _resolve_binary(self, name: str) -> str:
        """
        Проверка доступности бинарника в системе
        """
        path = shutil.which(name)
        if not path:
            raise RuntimeError(f"Required binary {name} not found in PATH")
        return path

    def _validate_headers(self):
        """
        Validate optional headers provided for web scanning
        """
        for k, v in self.headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("Headers must be string key-value pairs")
            if ':' in k:
                raise ValueError("Header name cannot contain ':'")

    def _prepare_headers(self) -> List[str]:
        """
        Преобразование headers в CLI флаги
        """
        if not self.headers:
            return []

        self._validate_headers(self.headers)
        flags = []
        for key, value in self.headers.items():
            flags.extend(["-H", f"{key}: {value}"])
        return flags

    def _build_base_command(self) -> List[str]:
        """
        Базовые проверки перед построением команды
        """
        return [self._resolve_binary(self.binary_name)]

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
        result = {
            "success": False,
            "output": "",
            "error": "",
            "returncode": -1
        }
        try:
            logger.debug(
                f"[{self.__class__.__name__}] Running command: "
                f"{' '.join(command)}"
            )
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=self.timeout
            )
            result.update({
                "success": True,
                "output": process.stdout.strip(),
                "error": process.stderr.strip(),
                "returncode": process.returncode
            })
            logger.info(
                f"[{self.__class__.__name__}] Command executed successfully"
            )
            # return process.stdout.strip()

        except subprocess.CalledProcessError as e:
            logger.error(
                f"[{self.__class__.__name__}] Command '{' '.join(command)}' "
                f"failed with error: {e}"
            )
            result.update({
                "output": e.stdout.strip(),
                "error": e.stderr.strip(),
                "returncode": e.returncode
            })

        except subprocess.TimeoutExpired:
            logger.error(
                f"[{self.__class__.__name__}] Timeout ({self.timeout}s) "
                f"expired for command: {' '.join(command)}"
            )
            result["error"] = (
                f"Timeout ({self.timeout}s) expired for command: "
                f"{' '.join(command)}"
            )

        except Exception as e:
            logger.exception(
                f"[{self.__class__.__name__}] Unexpected exception "
                f"while executing command: {' '.join(command)}. Exception: {e}"
            )
            result["error"] = f"Unexpected error: {str(e)}"

        return result

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """

        :param output: _description_
        :type output: str
        :return: _description_
        :rtype: List[Dict[str, Any]]
        """
        return []

    def _post_run(self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Common post-run actions (e.g., logging, result formatting)

        Override this method in a subclass
            for additional result handling if needed

        :param target: The target address or domain
        :param result: The raw result dictionary from the execute method
        :return: A dictionary containing the final processed results
        """
        if not result["success"]:
            return {
                "error": result["error"],
                "returncode": result["returncode"]
            }

        return {
            "result": result["output"],
            "parsed": self._parse_output(result["output"]),
        }

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
            return self._post_run(target_str, result)

        except Exception as e:
            logger.exception(
                f"Critical error in module {self.__class__.__name__}: {e}"
            )
            return {
                "error": str(e),
                "success": False,
                "tool": self.__class__.__name__
            }

    @classmethod
    def check_availability(cls) -> bool:
        """
        Check if the module is available for use

        :return: True if the module is available, False otherwise
        """
        version = cls.get_version()
        return {
            "available": version is not None,
            "version": version
        }

    @classmethod
    def _parse_version(cls, output: str) -> str:
        """
        Parse the version from the output of the command
        """
        match = re.search(r'\d+\.\d+\.\d+', output)
        return match.group(0) if match else "unknown"

    @classmethod
    def get_version(cls) -> Optional[str]:
        """
        Get version of tool
        """
        try:
            result = subprocess.run(
                [f"{cls.binary_name}", "--version"],
                capture_output=True,
                text=True,
                timeout=20
            )
            return cls._parse_version(result.stdout or result.stderr)
        except Exception as e:
            logger.error(
                f"[{cls.__name__}] Version check failed: {str(e)}"
            )
            return None
