import logging
import json
from typing import List, Union, Dict, Any
from dataclasses import fields
from bountyforge.core import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class SubfinderModule(Module):
    """
    Module for passive subdomain enumeration using subfinder

    The scan_type is fixed to RECON by default
    """
    binary_name = "subfinder"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        scan_type: ScanType = ScanType.RECON,
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

        command += [
            "-silent",
            "-all",
            "-recursive",
            "-json",
            "-disable-update-check"
        ]

        match self.target_type:
            case TargetType.FILE:
                command.extend(["-dL", target_str])
            case TargetType.SINGLE | TargetType.MULTIPLE:
                command.extend(["-d", target_str])
            case _:
                command.extend(["-d", target_str])

        if self.additional_flags:
            command.append(self.additional_flags)

        logger.info(f"Command: {command}")
        return command

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        return [
            json.loads(line) for line in output.splitlines() if line.strip()
        ]
