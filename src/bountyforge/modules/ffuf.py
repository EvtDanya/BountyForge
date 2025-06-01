import json
import logging
import subprocess
import re
from typing import Any, Dict, List, Union, Optional
from urllib.parse import urlparse

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
        wordlist: str = "./wordlists/web-content/common.txt",
        additional_flags: List[str] = None,
        rate_limit: int = 20,
        protocol: Optional[str] = None,
        **kwargs
    ) -> None:
        super().__init__(
            scan_type=scan_type,
            target=target,
            target_type=target_type,
            additional_flags=additional_flags,
            rate_limit=rate_limit
        )
        self.wordlist = wordlist
        self.protocol = protocol

    def _build_command(self, target_str: str) -> List[str]:
        parsed = urlparse(target_str) if "://" in target_str else None
        if parsed and parsed.scheme:
            scheme = parsed.scheme
            host = parsed.netloc
        else:
            scheme = self.protocol or "http"
            host = target_str

        cmd = [self._resolve_binary(self.binary_name)]
        cmd += ["-w", self.wordlist]
        cmd += ["-of", "json", "-json"]
        cmd += ["-s"]

        if self.scan_type == ScanType.SUBDOMAIN:
            # Host: FUZZ.target
            url_base = f"{scheme}://{host}"
            cmd += ["-u", url_base]
            cmd += ["-H", f"'Host: FUZZ.{host}'"]
        else:
            # /FUZZ
            url_base = f"{scheme}://{host}/FUZZ"
            cmd += ["-u", url_base]
            cmd += ["-recursion", "-recursion-depth", "2"]

        cmd += ["-r"]
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
                    for line in res["output"].splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            all_parsed.append({
                                "target": host,
                                "scan_type": self.scan_type.value,
                                "url":     obj.get("url"),
                                "status":  obj.get("status"),
                                "length":  obj.get("length"),
                            })
                        except json.JSONDecodeError:
                            # fallback: plain-text path
                            all_parsed.append({
                                "target": host,
                                "scan_type": self.scan_type.value,
                                "path": line
                            })
                        except Exception as e:
                            logger.exception(
                                f"[FfufModule] JSON parse error on {host}: {e}"
                            )

            except Exception as e:
                logger.exception(f"[FfufModule] Exception on {host}: {e}")
                all_results.append({
                    "target": host,
                    "scan_type": self.scan_type.value,
                    "error": str(e),
                    "success": False
                })

        return {
            "scan_type": self.scan_type.value,
            "result": all_results,
            "parsed": all_parsed
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
