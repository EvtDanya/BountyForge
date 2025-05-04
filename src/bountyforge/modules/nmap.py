import logging
import re
from typing import List, Union
from dataclasses import fields
from bountyforge.core import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class NmapModule(Module):
    """
    Nmap scanning module.

    This module performs an Nmap scan
    """
    binary_name = "nmap"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        scan_type: ScanType = ScanType.DEFAULT,
        additional_flags: List[str] = None,
        **kwargs
    ) -> None:
        # check for unexpected args
        # unexpected_args = set(kwargs) - {f.name for f in fields(self)}
        # if unexpected_args:
        #     logger.warning(
        #         f"Unexpected arguments: {', '.join(unexpected_args)}"
        #     )

        super().__init__(
            scan_type=scan_type,
            target=target,
            target_type=target_type,
            additional_flags=additional_flags
        )

    def _build_command(self, target_str: str) -> List[str]:
        command = super()._build_base_command()

        command += ["-Pn", "-p", "8080,53,135,445"]

        match self.scan_type:
            case ScanType.AGGRESSIVE:
                # Aggressive scan: faster timing, version detection,
                # OS detection, script scanning
                command.extend(["-T4", "-A", "-sV"])
            case ScanType.FULL:
                # Full port scan on all ports with aggressive flags
                command.extend(["-p-", "-T4", "-A", "-sV"])
            case _:
                command.extend(["-T4", "-sV"])

        match self.target_type:
            case TargetType.FILE:
                command.extend(["-iL", target_str])
            case TargetType.SINGLE | TargetType.MULTIPLE:
                command.append(target_str)
            case _:
                command.append(target_str)

        if self.additional_flags:
            command.append(self.additional_flags)

        logger.info(f"Command: {command}")
        return command

    @classmethod
    def _parse_version(cls, output: str) -> str:
        """
        Парсинг версии из вывода
        """
        match = re.search(r'Nmap version\s+(\d+\.\d+(?:\.\d+)?)', output)
        return match.group(1) if match else "unknown"
