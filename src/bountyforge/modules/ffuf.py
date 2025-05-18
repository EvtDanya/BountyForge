import json
import logging
import subprocess
import re
from typing import Any, Dict, List, Union, Optional

from bountyforge.core.module_base import Module, TargetType, ScanType

logger = logging.getLogger(__name__)


class FfufModule(Module):
    """
    ffuf в двух режимах, управляемых через scan_type:
    - ScanType.SUBDOMAIN: перебор поддоменов через Host: FUZZ.target
    - ScanType.DIRECTORY (или любой другой): классический /FUZZ
    """
    binary_name = "ffuf"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType = TargetType.SINGLE,
        scan_type: ScanType = ScanType.DIRECTORY,
        wordlist: str = "./wordlists/common.txt",
        additional_flags: List[str] = None,
        **kwargs
    ) -> None:
        super().__init__(
            scan_type=scan_type,
            target=target,
            target_type=target_type,
            additional_flags=additional_flags,
        )
        self.wordlist = wordlist

    def _build_command(self, target_str: str) -> List[str]:
        cmd = [self._resolve_binary(self.binary_name)]
        cmd += ["-w", self.wordlist]
        cmd += ["-of", "json", "-o", "-"]
        cmd += ["-silent"]

        if self.scan_type == ScanType.SUBDOMAIN:
            # поддомен через Host: FUZZ.target
            cmd += ["-u", f"https://{target_str}"]
            cmd += ["-H", f"Host: FUZZ.{target_str}"]
        else:
            # директории /FUZZ
            cmd += ["-u", f"https://{target_str}/FUZZ"]

        if self.additional_flags:
            cmd += self.additional_flags

        logger.info(f"Command: {cmd}")
        return cmd

    def run(self) -> Dict[str, Any]:
        raw = self._prepare_target()
        hosts = [
            raw
        ] if self.target_type == TargetType.SINGLE else raw.split(",")

        all_results = []
        all_parsed = []

        for host in hosts:
            try:
                self._pre_run(host)
                cmd = self._build_command(host)
                res = self._execute_command(cmd)
                record = {
                    "target": host,
                    "scan_type": self.scan_type.value,
                    "success": res.get("success", False),
                    "returncode": res.get("returncode", -1),
                    "error": res.get("error", ""),
                    "output": res.get("output", "")
                }
                all_results.append(record)

                if res.get("success"):
                    try:
                        data = json.loads(res["output"])
                        for e in data.get("results", []):
                            parsed = {
                                "target":    host,
                                "scan_type": self.scan_type.value,
                                "url":        e.get("url"),
                                "status":     e.get("status"),
                                "length":     e.get("length")
                            }
                            all_parsed.append(parsed)
                    except Exception as e:
                        logger.exception(
                            f"[FfufModule] JSON parse error on {host}: {e}"
                        )

            except Exception as e:
                logger.exception(f"[FfufModule] Exception on {host}: {e}")
                all_results.append({
                    "target":    host,
                    "scan_type": self.scan_type.value,
                    "error":     str(e),
                    "success":   False
                })

        return {
            "scan_type": self.scan_type.value,
            "result":    all_results,
            "parsed":    all_parsed
        }

    @classmethod
    def _parse_version(cls, output: str) -> str:
        """
        Parse the version from the output of the command
        """
        match = re.search(r'\d+\.\d+\.\d+(-\w+)?', output)
        return match.group(0) if match else "unknown"

    @classmethod
    def get_version(cls) -> Optional[str]:
        """
        Get version of tool
        """
        try:
            result = subprocess.run(
                [f"{cls.binary_name}", "-V"],
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
