import logging
from typing import List, Union
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
        wordlist: str = "subdomains.txt",
        additional_flags: List[str] = None
    ) -> None:
        self.wordlist = wordlist
        super().__init__(
            ScanType.DEFAULT,
            target,
            target_type,
            additional_flags
        )

    def _build_command(self, target_str: str) -> List[str]:
        super()._build_command(target_str)

        command = ["subbrute", "-d", target_str, "-w", self.wordlist]

        if self.additional_flags:
            command.extend(self.additional_flags)

        return command
