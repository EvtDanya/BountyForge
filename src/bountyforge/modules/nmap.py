import logging
from typing import List, Union
from bountyforge.core.module_base import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class NmapModule(Module):
    """
    Nmap scanning module.

    This module performs an Nmap scan
    """
    def __init__(
        self,
        scan_type: ScanType,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        additional_flags: List[str] = None
    ) -> None:
        super().__init__(scan_type, target, target_type, additional_flags)
        self.binary_name = "nmap"

    def _build_command(self, target_str: str) -> List[str]:
        command = super()._build_base_command()

        command += ["-Pn"]

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
            command.extend(self.additional_flags)

        return command
