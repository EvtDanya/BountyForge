import logging
from typing import List, Union
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

        command += ["-silent", "-all"]

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

# class ReconAbstractModule(abc.ABC):
#     """
#     Abstract class for recon submodules
#     """
#     def __init__(self):
#         pass


# class ReconModule:
#     def __init__(self, target: str):
#         self.target = target

#     def run_subprocess(self, cmd: list[str]) -> list[str]:
#         """
#         ["subfinder", "-d", self.target, "-silent"]
#         Run specified command

#         :param cmd: _description_
#         :type cmd: list[str]
#         :return: _description_
#         :rtype: list[str]
#         """
#         result = subprocess.run(
#             cmd, capture_output=True, text=True
#         )
#         return result.stdout.splitlines()

#     def filter_subdomains(self, subdomains: list[str]) -> list[str]:
#         """_summary_

#         :param subdomains: _description_
#         :type subdomains: list[str]
#         :return: _description_
#         :rtype: list[str]
#         """
#         live_subdomains = []
#         return live_subdomains

# def run(target: str) -> dict:
#     """
#     Простейшая функция разведки: возвращает базовую информацию о цели.
#     В дальнейшем можно расширить,
# добавив вызовы к API, проверку DNS, WHOIS и т.д.
#     """
#     # Пока возвращаем фиктивные данные
#     return {
#         "target": target,
#         "info": f"Собрана базовая информация о {target}"
#     }