import logging
import json
from typing import List, Union, Dict, Any
from dataclasses import fields
from bountyforge.core import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class HttpxModule(Module):
    """
    Module for initial reconnaissance using httpx

    Modes:
      - "recon": Detailed output (e.g., title, status code, CDN info)
      - "live": Minimal output (e.g., status code only)
    """
    binary_name = "httpx"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType,
        scan_type: ScanType = ScanType.RECON,
        exclude: List[str] = None,
        additional_flags: List[str] = None,
        rate_limit: int = 20,
        headers: dict = None,
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
            exclude=exclude,
            additional_flags=additional_flags,
            headers=headers,
            rate_limit=rate_limit
        )

    def _build_command(self, target_str: str) -> List[str]:
        """
        Build the httpx command based on the scan_type and target

        :param target: The target domain or URL
        :return: A list of command arguments to execute
        """
        command = super()._build_base_command()
        command += self._prepare_headers()

        command += ["-silent", "-j", "-disable-update-check"]

        match self.scan_type:
            case ScanType.RECON:
                # In reconnaissance scan_type, show title,
                # status code and CDN information
                command.extend(["-title", "-status-code", "-cdn"])
            case ScanType.LIVE:
                # In live scan_type, output is kept minimal
                command.append(["-status-code"])
            case _:
                command.append(["-status-code"])

        match self.target_type:
            case TargetType.FILE:
                command.extend(["-l", target_str])
            case TargetType.SINGLE | TargetType.MULTIPLE:
                command.extend(["-u", target_str])
            case _:
                command.extend(["-u", target_str])

        if self.additional_flags:
            command.extend(self.additional_flags)

        if self.exclude:
            command.extend(["-exclude", ",".join(self.exclude)])

        return command

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        return [
            json.loads(line) for line in output.splitlines() if line.strip()
        ]
