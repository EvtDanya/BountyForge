import logging
from typing import List, Union
from dataclasses import fields
from bountyforge.core import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class SubdomainBruteforceModule(Module):
    """
    Module for brute forcing subdomains using a subbrute
    """
    binary_name = "subbrute"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        scan_type: ScanType = ScanType.DEFAULT,
        additional_flags: List[str] = None,
        wordlist: str = "subdomains.txt",
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

        self.wordlist = wordlist

    def _build_command(self, target_str: str) -> List[str]:
        super()._build_command(target_str)

        command = ["subbrute", "-d", target_str, "-w", self.wordlist]

        if self.additional_flags:
            command.extend(self.additional_flags)

        return command
