import logging
import re
from typing import List, Union, Dict, Any
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
        exclude: List[str] = None,
        additional_flags: List[str] = None,
        rate_limit: int = 20,
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
            rate_limit=rate_limit
        )

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

        if self.exclude:
            command.extend(["--exclude", ",".join(self.exclude)])

        command += ["-min-rate", str(self.rate_limit)]
        logger.info(f"Command: {command}")
        return command

    @classmethod
    def _parse_version(cls, output: str) -> str:
        """
        Парсинг версии из вывода
        """
        match = re.search(r'Nmap version\s+(\d+\.\d+(?:\.\d+)?)', output)
        return match.group(1) if match else "unknown"

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse output from Nmap scan
        """
        lines = output.splitlines()
        results: List[Dict[str, Any]] = []
        port_line_re = re.compile(r'^(\d+/\w+)\s+(\w+)\s+(\S+)\s*(.*)$')

        report_re = re.search(
            r'Nmap scan report for\s+'
            r'(?P<name>\S+)'
            r'(?: \((?P<ip>\d+\.\d+\.\d+\.\d+)\))?',
            output
        )
        if report_re:
            name = report_re.group('name')
            ip = report_re.group('ip') or report_re.group('name')
        else:
            name = ip = None

        for line in lines:
            m = port_line_re.match(line.strip())
            if m:
                port, state, service, extra = m.groups()
                entry = {
                    "host": name,
                    "ip": ip,
                    "port": port,
                    "state": state,
                    "service": service,
                }
                if extra:
                    entry["info"] = extra
                results.append(entry)

        return results
