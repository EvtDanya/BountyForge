import os
import subprocess
import logging
import json
from typing import Any, Dict, List, Union
from dataclasses import fields
from bountyforge.core import Module, ScanType, TargetType

logger = logging.getLogger(__name__)


class NucleiModule(Module):
    """
    Nuclei scanner module.
    Uses `nuclei` CLI to scan targets with given templates.
    """
    templates_dir: str = "./nuclei-templates"
    binary_name = "nuclei"

    def __init__(
        self,
        target: Union[str, List[str]],
        target_type: TargetType,
        scan_type: ScanType = ScanType.DEFAULT,
        exclude: List[str] = None,
        additional_flags: List[str] = None,
        templates_dir: str = "",
        rate_limit: int = 20,
        **kwargs
    ) -> None:
        """
        :param target: Single target string or list of targets.
        :param target_type: SINGLE / MULTIPLE / FILE.
        :param templates_dir: Path to nuclei templates directory.
        :param scan_type: One of ScanType.
        :param additional_flags: Extra CLI flags.
        """
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
        self.templates_dir = templates_dir

    def _build_command(self, target_str: str) -> List[str]:
        """
        Construct the nuclei command based on target and configuration.
        """
        cmd = super()._build_base_command()
        cmd += ["-silent", "-j", "-disable-update-check", "-fr"]

        match self.target_type:
            case TargetType.FILE:
                cmd.extend(["-l", target_str])
            case TargetType.SINGLE | TargetType.MULTIPLE:
                cmd.extend(["-u", target_str])
            case _:
                cmd.extend(["-u", target_str])

        if self.templates_dir:
            cmd += ["-t", self.templates_dir]

        # match self.scan_type:
        #     case ScanType.AGGRESSIVE:
        #         # increase rate-limit for aggressive mode
        #         cmd += ["-rate-limit", "200"]
        #     case ScanType.FULL:
        #         # run all templates
        #         cmd += ["-all"]
        #     case ScanType.RECON:
        #         # recon mode: output extra metadata
        #         # cmd += ["-json"]
        #         pass
        #     case _:
        #         pass

        if self.additional_flags:
            cmd += self.additional_flags

        if self.exclude:
            cmd.extend(["-exclude-hosts", ",".join(self.exclude)])

        cmd += ["-rate-limit", str(self.rate_limit)]
        logger.info(f"Command: {cmd}")
        return cmd

    # def _post_run(
    #     self, target_str: str,
    #     result: Dict[str, Any]
    # ) -> Dict[str, Any]:
    #     """
    #     Parse nuclei JSON output (if any) or return raw output.
    #     """
    #     output = result.get("output", "")
    #     if output:
    #         try:
    #             parsed = [
    #                 json.loads(line) for line
    #                 in output.splitlines()
    #                 if line.strip()
    #             ]
    #             return {"parsed": parsed}
    #         except Exception:
    #             return {"result": output}
    #     return result

    def _validate_templates(self):
        """
        Validate PATH for templates
        """
        if not os.Path(self.template_dir).exists():
            raise Exception("Invalid template directory")

    @classmethod
    def update_templates(cls) -> None:
        """
        Update the nuclei templates to the latest version.
        """
        logger.info("Updating nuclei templates...")
        # if not os.path.exists(self.templates_dir):
        #     os.makedirs(self.templates_dir)

        cmd = [f"{cls.binary_name}", "-update-templates"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        logger.info(result.stdout or result.stderr)
        return cls._parse_version(result.stdout or result.stderr)

    @classmethod
    def update_nuclei(cls) -> None:
        """
        Update the nuclei binary to the latest version.
        """
        logger.info("Updating nuclei binary...")

        cmd = [f"{cls.binary_name}", "-update"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        logger.info(result.stdout or result.stderr)
        return cls._parse_version(result.stdout or result.stderr)

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        return [
            json.loads(line) for line in output.splitlines() if line.strip()
        ]
