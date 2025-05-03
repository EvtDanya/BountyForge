from typing import Any, Dict, List, Union
import os
import subprocess
import logging
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
        target_type: TargetType = TargetType.SINGLE,
        templates_dir: str = "",
        scan_type: ScanType = ScanType.DEFAULT,
        additional_flags: List[str] = None
    ) -> None:
        """
        :param target: Single target string or list of targets.
        :param target_type: SINGLE / MULTIPLE / FILE.
        :param templates_dir: Path to nuclei templates directory.
        :param scan_type: One of ScanType.
        :param additional_flags: Extra CLI flags.
        """
        super().__init__(
            scan_type=scan_type,
            target=target,
            target_type=target_type,
            additional_flags=additional_flags
        )
        self.templates_dir = templates_dir

    def _build_command(self, target_str: str) -> List[str]:
        """
        Construct the nuclei command based on target and configuration.
        """
        cmd = super()._build_base_command()
        cmd += ["-silent", "-stats", "-json", "-disable-update-check"]

        if self.target_type == TargetType.SINGLE:
            cmd += ["-u", target_str]
        else:
            cmd += ["-l", target_str]

        if self.templates_dir:
            cmd += ["-t", self.templates_dir]

        match self.scan_type:
            case ScanType.AGGRESSIVE:
                # increase rate-limit for aggressive mode
                cmd += ["-rate-limit", "200"]
            case ScanType.FULL:
                # run all templates
                cmd += ["-all"]
            case ScanType.RECON:
                # recon mode: output extra metadata
                cmd += ["-json"]
            case _:
                pass

        if self.additional_flags:
            cmd += self.additional_flags

        return cmd

    def _post_run(
        self, target_str: str,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Parse nuclei JSON output (if any) or return raw output.
        """
        output = result.get("output", "")
        # if JSON mode, try to parse each line as JSON
        if self.scan_type == ScanType.RECON and output:
            try:
                import json
                parsed = [
                    json.loads(line) for line
                    in output.splitlines()
                    if line.strip()
                ]
                return {"results": parsed}
            except Exception:
                # fallback to raw
                return {"output": output}
        return result

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
