import logging
from typing import List, Union
from bountyforge.core.module_base import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class HttpxModule(Module):
    """
    Module for initial reconnaissance using httpx

    Modes:
      - "recon": Detailed output (e.g., title, status code, CDN info)
      - "live": Minimal output (e.g., status code only)
    """
    def __init__(
        self,
        mode: str = "recon",
        target: Union[str, List[str]] = None,
        target_type: TargetType = TargetType.SINGLE,
        additional_flags: List[str] = None
    ) -> None:
        # For httpx, we use RECON as the scan type by default
        super().__init__(ScanType.RECON, target, target_type, additional_flags)
        self.mode = mode.lower()
        self.binary_name = "httpx"

    def _build_command(self, target_str: str) -> List[str]:
        """
        Build the httpx command based on the scan_type and target

        :param target: The target domain or URL
        :return: A list of command arguments to execute
        """
        command = super()._build_base_command()
        command += self._prepare_headers(self.headers)

        command += ["-silent"]

        match self.mode:
            case ScanType.RECON:
                # In reconnaissance scan_type, show title,
                # status code and CDN information
                command.extend(["-title", "-status-code", "-cdn"])
            case ScanType.LIVE:
                # In live scan_type, output is kept minimal
                command.extend(["-status-code"])
            case _:
                command.extend(["-status-code"])

        match self.target_type:
            case TargetType.FILE:
                command.extend(["-l", target_str])
            case TargetType.SINGLE | TargetType.MULTIPLE:
                command.append(["-u", target_str])
            case _:
                command.append(["-u", target_str])

        if self.additional_flags:
            command.extend(self.additional_flags)

        return command
